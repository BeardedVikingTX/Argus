#!/usr/bin/env python3
"""
test_connection.py — Argus integration health check
─────────────────────────────────────────────────────────────────────────────

Verifies every external integration Argus depends on, using only HTTP.
No SSH required. Every diagnostic can be run against a remote server.

Sections:
  Config        — config.py loads, keys are well-formed
  Filesystem    — wildcard.txt, output/, config.py gitignored
  Bridge ping   — api.php reachable, DB connected, PHP version
  Deployment    — which actions exist on the server (old vs new api.php)
  Bridge auth   — signed request, shows the EXACT server response
  OOB receiver  — oast.*/check.php responds, /?mode=health responds
  Email IMAP    — connectivity only (does NOT read messages)
  Email SMTP    — connectivity only (does NOT send mail)

Usage:
    python3 test_connection.py                 everything
    python3 test_connection.py --no-email      skip IMAP/SMTP
    python3 test_connection.py --bridge-only   only bridge checks
    python3 test_connection.py --json          JSON output
    python3 test_connection.py --verbose       show full HTTP exchanges
    python3 test_connection.py --no-color      disable ANSI

Exit codes:
    0  all checks passed (warnings OK)
    1  one or more checks failed
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

# ═════════════════════════════════════════════════════════════════════════════
#  DEPENDENCIES
# ═════════════════════════════════════════════════════════════════════════════

try:
    import requests
    REQUESTS_OK = True
    REQUESTS_VERSION = requests.__version__
except ImportError:
    requests = None
    REQUESTS_OK = False
    REQUESTS_VERSION = ""

# ═════════════════════════════════════════════════════════════════════════════
#  PATHS / CONFIG
# ═════════════════════════════════════════════════════════════════════════════

BASE_DIR   = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"

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


def _cfg(key: str, default: Any = None) -> Any:
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


# ═════════════════════════════════════════════════════════════════════════════
#  TERMINAL PALETTE
# ═════════════════════════════════════════════════════════════════════════════

_USE_COLOR = True
_VERBOSE   = False

C = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[90m",
    "red":     "\033[31m",
    "green":   "\033[32m",
    "yellow":  "\033[33m",
    "cyan":    "\033[36m",
    "magenta": "\033[35m",
}

STATUS_GLYPHS = {
    "ok":   ("\033[32m", "✓"),
    "warn": ("\033[33m", "⚠"),
    "fail": ("\033[31m", "✗"),
    "skip": ("\033[90m", "·"),
}


def _c(key: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{C.get(key, '')}{text}{C['reset']}"


def _hline(width: int = 71, color: str = "cyan") -> str:
    return _c(color, "═" * width)


def _gap() -> None:
    print()


# ═════════════════════════════════════════════════════════════════════════════
#  RESULT MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CheckResult:
    name: str
    status: str           # "ok" | "warn" | "fail" | "skip"
    message: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "detail": self.detail,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP DEBUG HELPER
# ═════════════════════════════════════════════════════════════════════════════

def _debug_request(
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Optional[bytes] = None,
    timeout: int = 15,
) -> "requests.Response":
    """
    Make an HTTP request and (if --verbose) dump the full exchange to stdout.
    Sensitive header values are truncated in the dump.
    """
    if _VERBOSE:
        print(f"  {_c('dim', '→')} {method} {url}")
        for k, v in (headers or {}).items():
            v_str = str(v)
            if k.lower() in ("x-argus-sig", "cookie", "authorization"):
                v_str = v_str[:8] + "…" + v_str[-4:] if len(v_str) > 12 else v_str
            print(f"    {_c('dim', f'{k}: {v_str}')}")
        if body:
            print(f"    {_c('dim', f'body: {body[:200]!r}')}")

    r = requests.request(
        method, url,
        headers=headers or {},
        data=body,
        timeout=timeout,
    )

    if _VERBOSE:
        print(f"  {_c('dim', '←')} HTTP {r.status_code}")
        for k, v in r.headers.items():
            print(f"    {_c('dim', f'{k}: {v}')}")
        preview = r.text[:400].replace("\n", " ")
        print(f"    {_c('dim', preview)}")

    return r


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — CONFIG
# ═════════════════════════════════════════════════════════════════════════════

def check_config() -> list[CheckResult]:
    results: list[CheckResult] = []

    if not CFG_LOADED:
        return [CheckResult("config.py", "fail", "not found")]

    results.append(CheckResult("config.py", "ok", "loaded"))

    errors, warnings = CFG.validate()
    for e in errors:
        results.append(CheckResult("validation", "fail", e))
    for w in warnings:
        results.append(CheckResult("validation", "warn", w))

    for k, v in CFG.summary().items():
        results.append(CheckResult(k, "ok", str(v)))

    if REQUESTS_OK:
        results.append(CheckResult("requests", "ok", REQUESTS_VERSION))
    else:
        results.append(CheckResult("requests", "fail",
                                   "not installed — run `pip install requests`"))

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — FILESYSTEM + GIT HYGIENE
# ═════════════════════════════════════════════════════════════════════════════

def check_filesystem() -> list[CheckResult]:
    results: list[CheckResult] = []

    wildcard = BASE_DIR / "wildcard.txt"
    if wildcard.exists():
        domains = [
            l.strip() for l in wildcard.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        if domains:
            results.append(CheckResult(
                "wildcard.txt", "ok", f"{len(domains)} domain(s)",
                detail=", ".join(domains[:5]),
            ))
        else:
            results.append(CheckResult("wildcard.txt", "warn", "exists but empty"))
    else:
        results.append(CheckResult("wildcard.txt", "warn",
                                   "not found (run `echo example.com > wildcard.txt`)"))

    if OUTPUT_DIR.exists():
        results.append(CheckResult("output/", "ok", str(OUTPUT_DIR)))
    else:
        results.append(CheckResult("output/", "warn", "not found — main.py will create it"))

    if CFG_LOADED:
        try:
            r = subprocess.run(
                ["git", "check-ignore", "-q", "config.py"],
                cwd=str(BASE_DIR), timeout=5,
            )
            if r.returncode == 0:
                results.append(CheckResult("config.py gitignored", "ok", "yes"))
            elif r.returncode == 1:
                results.append(CheckResult(
                    "config.py gitignored", "fail",
                    "NOT gitignored — STOP, do not commit",
                ))
            else:
                results.append(CheckResult("config.py gitignored", "skip", "git check failed"))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            results.append(CheckResult("config.py gitignored", "skip", "git not available"))

    for name in ("main.py", "db.py", "tools.py"):
        if (BASE_DIR / name).exists():
            results.append(CheckResult(name, "ok", "present"))
        else:
            results.append(CheckResult(name, "warn", "not found"))

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — BRIDGE PING (no auth)
# ═════════════════════════════════════════════════════════════════════════════

def check_bridge_ping() -> list[CheckResult]:
    results: list[CheckResult] = []

    url = _cfg("BRIDGE_URL", "")
    if not url:
        return [CheckResult("bridge ping", "skip", "BRIDGE_URL not set")]
    if not _cfg("BRIDGE_ENABLED", False):
        return [CheckResult("bridge ping", "skip", "BRIDGE_ENABLED is False")]
    if not REQUESTS_OK:
        return [CheckResult("bridge ping", "fail", "requests not installed")]

    try:
        r = _debug_request("GET", f"{url}?action=ping", timeout=15)
    except Exception as e:
        return [CheckResult("bridge reachable", "fail", str(e)[:120])]

    if r.status_code != 200:
        return [CheckResult("bridge reachable", "fail", f"HTTP {r.status_code}")]

    try:
        data = r.json()
    except Exception:
        return [CheckResult("bridge reachable", "fail", "response is not JSON")]

    if not data.get("ok"):
        return [CheckResult("bridge reachable", "fail", f"response not ok: {str(data)[:100]}")]

    results.append(CheckResult("bridge reachable", "ok", url))
    results.append(CheckResult("bridge service", "ok", data.get("service", "?")))

    db_state = data.get("db_connected")
    if db_state is True:
        results.append(CheckResult("bridge DB", "ok", "connected"))
    elif db_state is False:
        results.append(CheckResult(
            "bridge DB", "fail",
            "not connected — check ARGUS_DB_PASS in server config.php",
        ))
    elif "db_connected" not in data:
        results.append(CheckResult(
            "bridge DB", "warn",
            "no db_connected field — OLD api.php deployed",
            detail="redeploy api.php with the updated ping handler",
        ))

    if "php_version" in data:
        results.append(CheckResult("PHP", "ok", data["php_version"]))
    else:
        results.append(CheckResult(
            "PHP", "warn",
            "no php_version field — OLD api.php deployed",
        ))

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — DEPLOYMENT PROBE (which actions exist, no auth needed)
# ═════════════════════════════════════════════════════════════════════════════

def check_bridge_deployment() -> list[CheckResult]:
    """
    Probe which actions exist on the server by sending unauthenticated POSTs
    and inspecting the response:
      404 'unknown action'  →  action NOT deployed
      401 'request rejected'→  action EXISTS, auth failed (expected)
      200                   →  action is public (only 'ping' should be)
    """
    results: list[CheckResult] = []

    url = _cfg("BRIDGE_URL", "")
    if not url:
        return [CheckResult("deployment", "skip", "BRIDGE_URL not set")]
    if not _cfg("BRIDGE_ENABLED", False):
        return [CheckResult("deployment", "skip", "BRIDGE_ENABLED is False")]
    if not REQUESTS_OK:
        return [CheckResult("deployment", "fail", "requests not installed")]

    # Baseline: send a nonexistent action, expect 404 + "unknown action"
    try:
        r = _debug_request(
            "POST", f"{url}?action=argus_nonexistent_probe_xyz",
            headers={"Content-Type": "application/json"},
            body=b"{}",
        )
        if r.status_code == 404 and "unknown action" in r.text.lower():
            results.append(CheckResult(
                "action dispatch", "ok", "responds to unknown actions with 404",
            ))
        else:
            results.append(CheckResult(
                "action dispatch", "warn",
                f"expected 404, got HTTP {r.status_code}",
                detail=r.text[:100],
            ))
    except Exception as e:
        return [CheckResult("action dispatch", "fail", f"probe failed: {str(e)[:100]}")]

    # Probe known actions — each should EXIST (401, not 404)
    known_actions = [
        "health.tables",
        "scan.create", "scan.finish", "stage.save",
        "hosts.upsert", "endpoints.upsert", "findings.upsert",
        "oob.sync",
        "query.stats", "query.findings",
    ]
    missing: list[str] = []
    present: list[str] = []

    for action in known_actions:
        try:
            r = _debug_request(
                "POST", f"{url}?action={action}",
                headers={"Content-Type": "application/json"},
                body=b"{}",
                timeout=10,
            )
            if r.status_code == 404:
                missing.append(action)
            else:
                present.append(action)
        except Exception:
            missing.append(action)

    if not missing:
        results.append(CheckResult(
            "deployed actions", "ok",
            f"all {len(known_actions)} present",
        ))
    elif len(missing) == len(known_actions):
        results.append(CheckResult(
            "deployed actions", "fail",
            "none found — api.php not deployed, or wrong URL",
        ))
    else:
        results.append(CheckResult(
            "deployed actions", "warn",
            f"{len(missing)}/{len(known_actions)} missing",
            detail=f"missing: {', '.join(missing)}",
        ))

        # Specific callout for the most common case: old api.php
        if "health.tables" in missing:
            results.append(CheckResult(
                "health.tables", "fail",
                "action missing — this is why auth testing fails",
                detail="redeploy api.php (see the Fix section below)",
            ))

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — BRIDGE AUTH (own signing, shows raw server response)
# ═════════════════════════════════════════════════════════════════════════════

def check_bridge_auth() -> list[CheckResult]:
    """
    Sign a request ourselves (bypassing db.py) so we can see the exact
    server response — status code, error field, everything.
    """
    results: list[CheckResult] = []

    url = _cfg("BRIDGE_URL", "")
    key = _cfg("BRIDGE_KEY", "")

    if not url or not key:
        return [CheckResult("bridge auth", "skip", "BRIDGE_URL or BRIDGE_KEY not set")]
    if not _cfg("BRIDGE_ENABLED", False):
        return [CheckResult("bridge auth", "skip", "BRIDGE_ENABLED is False")]
    if not REQUESTS_OK:
        return [CheckResult("bridge auth", "fail", "requests not installed")]

    # ── Pre-flight: check key shape locally ────────────────────────────────
    key_len = len(key)
    if key_len != 64:
        results.append(CheckResult(
            "key length", "fail",
            f"BRIDGE_KEY is {key_len} chars, expected 64",
            detail="run `python3 make_bridge_key.py` to generate a valid one",
        ))
        # Don't try HTTP — the request would fail anyway
        return results

    if not re.fullmatch(r"[a-f0-9]+", key):
        results.append(CheckResult(
            "key format", "fail",
            "BRIDGE_KEY contains non-hex characters",
            detail="only 0-9a-f allowed",
        ))
        return results

    key_id = key[:8]
    results.append(CheckResult("sending key_id", "ok", key_id))
    results.append(CheckResult("sending key_len", "ok", str(key_len)))

    # ── Build and send the signed request ──────────────────────────────────
    body = b"{}"
    ts = str(int(time.time()))
    sig = hmac.new(
        key.encode("utf-8"),
        ts.encode("utf-8") + b"." + body,
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Argus-Key":  key_id,
        "X-Argus-Ts":   ts,
        "X-Argus-Sig":  sig,
    }

    try:
        r = _debug_request(
            "POST", f"{url}?action=health.tables",
            headers=headers, body=body, timeout=15,
        )
    except Exception as e:
        results.append(CheckResult("bridge auth", "fail", f"request failed: {str(e)[:100]}"))
        return results

    # ── Interpret the response ─────────────────────────────────────────────
    if r.status_code == 200:
        try:
            data = r.json()
        except Exception:
            data = {}

        if data.get("ok"):
            results.append(CheckResult("bridge auth", "ok", "HMAC accepted"))
            results.append(CheckResult("bridge database", "ok", data.get("db", "?")))

            tables = data.get("tables", {})
            if tables:
                results.append(CheckResult("bridge tables", "ok", f"{len(tables)} table(s)"))
                for name, count in tables.items():
                    if count < 0:
                        results.append(CheckResult(f"  {name}", "warn", "unreadable"))
                    else:
                        results.append(CheckResult(f"  {name}", "ok", f"{count} row(s)"))
            else:
                results.append(CheckResult(
                    "bridge tables", "warn",
                    "no tables — run install.php on the server",
                ))
        else:
            results.append(CheckResult(
                "bridge auth", "fail",
                data.get("error", "unknown error")[:100],
            ))

    elif r.status_code == 404:
        results.append(CheckResult(
            "bridge auth", "fail",
            "health.tables not deployed — OLD api.php on server",
            detail="redeploy api.php with the health.tables action",
        ))

    elif r.status_code == 401:
        # Try to read the error field
        error_text = ""
        try:
            error_text = r.json().get("error", "")
        except Exception:
            error_text = r.text[:100]

        if error_text == "request rejected" or not error_text:
            # Server is NOT in debug mode
            results.append(CheckResult(
                "bridge auth", "fail",
                "server rejected the request (auth failed)",
            ))
            results.append(CheckResult(
                "diagnosis", "warn",
                "server hides the exact reason",
                detail="enable ARGUS_DEBUG in server config.php",
            ))
            _diagnose_auth_manually(results, url, key, ts, sig)
        else:
            # Server IS in debug mode — we have the real reason
            err = error_text.lower()
            if "key id" in err:
                results.append(CheckResult(
                    "bridge auth", "fail",
                    "key_id mismatch",
                    detail=f"server's ARGUS_BRIDGE_KEY_ID ≠ {key_id}",
                ))
                results.append(CheckResult(
                    "fix", "warn",
                    f"set ARGUS_BRIDGE_KEY_ID = '{key_id}' in server config.php",
                ))
            elif "signature" in err:
                results.append(CheckResult(
                    "bridge auth", "fail",
                    "signature mismatch",
                    detail="server's ARGUS_BRIDGE_SECRET ≠ your BRIDGE_KEY",
                ))
                results.append(CheckResult(
                    "fix", "warn",
                    "set ARGUS_BRIDGE_SECRET = BRIDGE_KEY in server config.php",
                ))
            elif "timestamp" in err:
                results.append(CheckResult(
                    "bridge auth", "fail",
                    "timestamp out of window (clock skew)",
                    detail="server clock differs from local — likely hosting issue",
                ))
            else:
                results.append(CheckResult(
                    "bridge auth", "fail", error_text[:100],
                ))
    else:
        results.append(CheckResult(
            "bridge auth", "fail",
            f"unexpected HTTP {r.status_code}",
            detail=r.text[:100],
        ))

    return results


def _diagnose_auth_manually(
    results: list[CheckResult],
    url: str, key: str, ts: str, sig: str,
) -> None:
    """When the server hides the error, give the user the exact tools."""
    key_id = key[:8]

    curl_cmd = (
        f"curl -X POST '{url}?action=health.tables' "
        f"-H 'Content-Type: application/json' "
        f"-H 'X-Argus-Key: {key_id}' "
        f"-H 'X-Argus-Ts: {ts}' "
        f"-H 'X-Argus-Sig: {sig}' "
        f"-d '{{}}'"
    )
    results.append(CheckResult(
        "reproduce", "warn", "run this to see the raw response:",
        detail=curl_cmd[:180],
    ))

    # Compare the 3 values that must match on the server
    results.append(CheckResult(
        "server check 1", "warn",
        f"ARGUS_BRIDGE_KEY_ID    should be  '{key_id}'",
    ))
    results.append(CheckResult(
        "server check 2", "warn",
        f"ARGUS_BRIDGE_SECRET    should be  '{key[:32]}…' (64 chars total)",
    ))
    results.append(CheckResult(
        "server check 3", "warn",
        "ARGUS_DEBUG            set to  true  (temporarily)",
        detail="re-run this script after enabling — you'll see the exact failure",
    ))
    results.append(CheckResult(
        "where to edit", "warn",
        "cPanel → File Manager → bug-bounty.beardedviking.org → config.php",
    ))


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — OAST RECEIVER
# ═════════════════════════════════════════════════════════════════════════════

def check_oast() -> list[CheckResult]:
    results: list[CheckResult] = []

    domain = _cfg("OAST_DOMAIN", "")
    mode = _cfg("OAST_MODE", "disabled")

    if mode == "disabled" or not domain:
        return [CheckResult("OAST", "skip", "disabled")]

    if not REQUESTS_OK:
        return [CheckResult("OAST", "fail", "requests not installed")]

    # Probe with a short invalid token — should get a clean 400
    try:
        r = _debug_request(
            "GET", f"https://{domain}/check.php?token=short",
            timeout=15,
        )
        if r.status_code == 200:
            results.append(CheckResult("OAST check.php", "ok", "responds"))
        elif r.status_code == 400:
            results.append(CheckResult(
                "OAST check.php", "ok",
                "responds with 400 for short tokens (correct)",
            ))
        else:
            results.append(CheckResult(
                "OAST check.php", "warn",
                f"HTTP {r.status_code}",
            ))
    except Exception as e:
        return [CheckResult("OAST check.php", "fail", str(e)[:100])]

    # Probe with a valid-length token — should return found:false
    try:
        r = _debug_request(
            "GET", f"https://{domain}/check.php?token=0000000000000000",
            timeout=15,
        )
        if r.status_code == 200:
            try:
                data = r.json()
                if "found" in data:
                    results.append(CheckResult(
                        "OAST token lookup", "ok",
                        "returns valid JSON with 'found' key",
                    ))
                else:
                    results.append(CheckResult(
                        "OAST token lookup", "warn",
                        f"unexpected response: {str(data)[:80]}",
                    ))
            except Exception:
                results.append(CheckResult(
                    "OAST token lookup", "warn",
                    "response is not JSON",
                ))
    except Exception:
        pass

    # Health endpoint
    try:
        r = _debug_request("GET", f"https://{domain}/?mode=health", timeout=10)
        if r.status_code == 200:
            results.append(CheckResult("OAST health", "ok", "OK"))
    except Exception:
        pass

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — IMAP (DIAGNOSTIC ONLY)
# ═════════════════════════════════════════════════════════════════════════════

def check_imap() -> list[CheckResult]:
    """
    DIAGNOSTIC ONLY.
    Verifies IMAP server reachability and credentials.
    Does NOT read message content, does NOT mark read, does NOT extract
    any links. Argus never automates account registration.
    """
    results: list[CheckResult] = []

    host     = _cfg("EMAIL_HOST", "")
    user     = _cfg("EMAIL_USER", "")
    password = _cfg("EMAIL_PASS", "")
    port     = int(_cfg("EMAIL_IMAP_PORT", 993) or 993)

    if not (host and user and password):
        return [CheckResult("IMAP", "skip",
                            "EMAIL_HOST / EMAIL_USER / EMAIL_PASS not configured")]

    try:
        import imaplib
        import ssl
    except ImportError:
        return [CheckResult("IMAP", "fail", "imaplib not available")]

    try:
        ctx = ssl.create_default_context()
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
        results.append(CheckResult("IMAP connect", "ok", f"{host}:{port} (TLS)"))
    except Exception as e:
        return [CheckResult("IMAP connect", "fail", str(e)[:120])]

    try:
        conn.login(user, password)
        results.append(CheckResult("IMAP login", "ok", f"as {user}"))
    except imaplib.IMAP4.error as e:
        results.append(CheckResult("IMAP login", "fail", str(e)[:120]))
        try: conn.logout()
        except Exception: pass
        return results

    try:
        status, data = conn.select("INBOX", readonly=True)
        if status == "OK" and data and data[0]:
            count = len(data[0].split())
            results.append(CheckResult("IMAP INBOX", "ok", f"{count} message(s)"))
    except Exception as e:
        results.append(CheckResult("IMAP INBOX", "warn", str(e)[:120]))

    # Folder parsing — fixed to handle quoted, unquoted, and NIL delimiter
    try:
        status, folders = conn.list()
        if status == "OK" and folders:
            names: list[str] = []
            for f in folders:
                raw = f.decode("utf-8", "ignore") if isinstance(f, bytes) else str(f)
                quoted = re.findall(r'"([^"]*)"', raw)
                if len(quoted) >= 2:
                    names.append(quoted[-1])
                elif quoted:
                    tokens = raw.rsplit(None, 1)
                    if tokens and tokens[-1] != quoted[0]:
                        names.append(tokens[-1])
                    else:
                        names.append(quoted[0])
                else:
                    tokens = raw.rsplit(None, 1)
                    if tokens:
                        names.append(tokens[-1])
            results.append(CheckResult(
                "IMAP folders", "ok",
                f"{len(names)} folder(s)",
                detail=", ".join(n for n in names[:8] if n),
            ))
    except Exception as e:
        results.append(CheckResult("IMAP folders", "warn", str(e)[:120]))

    try: conn.logout()
    except Exception: pass

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  CHECK — SMTP (DIAGNOSTIC ONLY)
# ═════════════════════════════════════════════════════════════════════════════

def check_smtp() -> list[CheckResult]:
    """
    DIAGNOSTIC ONLY.
    Verifies SMTP server reachability and credentials.
    Does NOT send email.
    """
    results: list[CheckResult] = []

    host     = _cfg("EMAIL_HOST", "")
    user     = _cfg("EMAIL_USER", "")
    password = _cfg("EMAIL_PASS", "")
    port     = int(_cfg("EMAIL_SMTP_PORT", 465) or 465)

    if not (host and user and password):
        return [CheckResult("SMTP", "skip",
                            "EMAIL_HOST / EMAIL_USER / EMAIL_PASS not configured")]

    try:
        import smtplib
        import ssl
    except ImportError:
        return [CheckResult("SMTP", "fail", "smtplib not available")]

    try:
        ctx = ssl.create_default_context()
        server = smtplib.SMTP_SSL(host, port, context=ctx, timeout=15)
        results.append(CheckResult("SMTP connect", "ok", f"{host}:{port} (TLS)"))
    except Exception as e:
        return [CheckResult("SMTP connect", "fail", str(e)[:120])]

    try:
        try:
            server.ehlo()
            results.append(CheckResult("SMTP EHLO", "ok", "accepted"))
        except smtplib.SMTPException as e:
            results.append(CheckResult("SMTP EHLO", "warn", str(e)[:120]))

        try:
            server.login(user, password)
            results.append(CheckResult("SMTP login", "ok", f"as {user}"))
        except smtplib.SMTPAuthenticationError as e:
            results.append(CheckResult("SMTP login", "fail", str(e)[:120]))
        except Exception as e:
            results.append(CheckResult("SMTP login", "warn", str(e)[:120]))
    finally:
        try: server.quit()
        except Exception: pass

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT RENDERING
# ═════════════════════════════════════════════════════════════════════════════

def show_banner() -> None:
    _gap()
    print("  " + _hline(71))
    print("  " + _c("cyan", _c("bold", "ARGUS")) + " // "
          + _c("bold", "test_connection.py") + " — integration health check")
    print("  " + _hline(71))
    _gap()


def show_section(index: int, total: int, name: str) -> None:
    _gap()
    print("  " + _c("cyan", f"[{index}/{total}]") + " " + _c("bold", name))
    print("  " + _c("dim", "─" * 69))


def print_result(r: CheckResult) -> None:
    color, glyph = STATUS_GLYPHS.get(r.status, ("", "?"))
    prefix = f"  {_c(color, glyph)}  {r.name:<28} {r.message}"
    if r.detail:
        prefix += "  " + _c("dim", f"({r.detail})")
    print(prefix)


def show_summary(counts: dict[str, int]) -> None:
    _gap()
    print("  " + _hline(71))

    total = sum(counts.values())
    parts = []
    if counts["ok"]:
        parts.append(_c("green", f"{counts['ok']} passed"))
    if counts["warn"]:
        parts.append(_c("yellow", f"{counts['warn']} warning(s)"))
    if counts["fail"]:
        parts.append(_c("red", f"{counts['fail']} failed"))
    if counts["skip"]:
        parts.append(_c("dim", f"{counts['skip']} skipped"))

    if counts["fail"] > 0:
        status = _c("red", "HEALTH: DEGRADED")
    elif counts["warn"] > 0:
        status = _c("yellow", "HEALTH: OK with warnings")
    else:
        status = _c("green", "HEALTH: ALL GREEN")

    print(f"  {status}  —  " + " · ".join(parts) + f"  ({total} checks)")
    print("  " + _hline(71))
    _gap()


def show_next_steps(results: list[CheckResult]) -> None:
    """Render actionable next steps based on which checks failed."""
    fails = [r for r in results if r.status == "fail"]
    warns = [r for r in results if r.status == "warn"]

    if not fails and not warns:
        return

    print("  " + _hline(71, "yellow"))
    print("  " + _c("yellow", _c("bold", "NEXT STEPS")))
    print("  " + _hline(71, "yellow"))
    _gap()

    # Collect specific hints from failed checks
    hints: list[str] = []

    for r in fails + warns:
        name = r.name.lower()
        msg = r.message.lower()

        if "bridge_key" in name and "length" in msg:
            hints.append("Run `python3 make_bridge_key.py` and update config.py")
            hints.append("Then update BOTH values in server config.php")

        elif "key_id mismatch" in name or ("key id" in msg and "mismatch" in msg):
            hints.append("Server config.php has the wrong ARGUS_BRIDGE_KEY_ID")
            hints.append(f"Set it to: {_cfg('BRIDGE_KEY', '')[:8]}")

        elif "signature mismatch" in name or ("signature" in msg and "mismatch" in msg):
            hints.append("Server config.php has the wrong ARGUS_BRIDGE_SECRET")
            hints.append("Copy the FULL BRIDGE_KEY into ARGUS_BRIDGE_SECRET")

        elif "health.tables" in name or "health.tables" in msg:
            hints.append("Server api.php is missing the health.tables action")
            hints.append("Redeploy the updated api.php via cPanel File Manager")

        elif "not deployed" in msg or "not deployed" in r.detail.lower():
            hints.append("api.php is old or missing — redeploy it")

        elif "db_connected" in msg or "bridge db" in name:
            hints.append("Server can't reach MySQL — check ARGUS_DB_PASS in config.php")

        elif "not gitignored" in msg:
            hints.append("Add config.py to .gitignore and untrack it")

        elif "requests" in msg and "not installed" in msg:
            hints.append("Run `pip install requests` inside the venv")

        elif "imap" in name and "folders" in name:
            pass  # cosmetic — skip

    # De-duplicate
    seen: set[str] = set()
    unique_hints: list[str] = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            unique_hints.append(h)

    if unique_hints:
        for i, h in enumerate(unique_hints, 1):
            print(f"  {_c('cyan', f'{i}.')} {h}")
        _gap()

    print("  " + _c("dim", "Deploy files via cPanel → File Manager → bug-bounty.beardedviking.org"))
    print("  " + _c("dim", "No SSH required. Everything is HTTP-based."))
    _gap()
    print("  " + _hline(71, "yellow"))
    _gap()


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main(argv: Optional[list[str]] = None) -> int:
    global _USE_COLOR, _VERBOSE

    parser = argparse.ArgumentParser(
        prog="test_connection.py",
        description="Argus integration health check (HTTP-based, no SSH required).",
    )
    parser.add_argument("--no-email", action="store_true",
                        help="skip IMAP and SMTP checks")
    parser.add_argument("--bridge-only", action="store_true",
                        help="only check the PHP bridge")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of human output")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="show full HTTP exchanges for debugging")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colors")
    args = parser.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False
    if args.verbose:
        _VERBOSE = True

    # Build section list
    sections: list[tuple[str, Callable[[], list[CheckResult]]]] = [
        ("Config",         check_config),
        ("Filesystem",     check_filesystem),
    ]
    if not args.bridge_only:
        sections.append(("Bridge connectivity",    check_bridge_ping))
    sections.append(("Bridge deployment",      check_bridge_deployment))
    sections.append(("Bridge authentication",  check_bridge_auth))
    if not args.bridge_only:
        sections.append(("OOB receiver",       check_oast))
    if not args.no_email and not args.bridge_only:
        sections.append(("Email — IMAP (diagnostic only)", check_imap))
        sections.append(("Email — SMTP (diagnostic only)", check_smtp))

    all_results: list[CheckResult] = []
    json_out: dict = {"sections": {}}

    if not args.json:
        show_banner()

    for i, (name, fn) in enumerate(sections, 1):
        if not args.json:
            show_section(i, len(sections), name)

        try:
            results = fn()
        except Exception as e:
            results = [CheckResult(name, "fail", f"exception: {str(e)[:100]}")]

        for r in results:
            if not args.json:
                print_result(r)
            all_results.append(r)

        if args.json:
            json_out["sections"][name] = [r.to_dict() for r in results]

    # Summary
    counts = {"ok": 0, "warn": 0, "fail": 0, "skip": 0}
    for r in all_results:
        counts[r.status] = counts.get(r.status, 0) + 1

    if args.json:
        json_out["summary"] = counts
        print(json.dumps(json_out, indent=2))
    else:
        show_summary(counts)
        show_next_steps(all_results)

    return 0 if counts["fail"] == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{_c('yellow', 'Interrupted.')}")
        sys.exit(130)
