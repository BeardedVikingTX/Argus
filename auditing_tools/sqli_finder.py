#!/usr/bin/env python3
"""auditing_tools/sqli_finder.py — SQL Injection Auditor (STUB)

NOTE: This file previously contained a copy of the IDOR finder. The real
SQLi finder has not been written yet. This stub keeps the pipeline intact
by raising NotImplementedError, which main.py treats as "module not yet
implemented" — same behavior as a missing import, but with a clear message.

The real IDOR finder lives in auditing_tools/idor_finder.py and is
unaffected by this stub.

To implement: follow the pattern in auditing_tools/open_redirect_finder.py
or auditing_tools/ssrf_finder.py — load URLs, inject payloads per parameter,
diff responses against a baseline, write findings to sqli_findings.json.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional


def run_sqli_scan(
    input_file: Path,
    outdir: Path,
    headers: Optional[dict[str, str]] = None,
    **kwargs: Any,
) -> None:
    raise NotImplementedError(
        "sqli_finder.py is a placeholder — the real SQLi finder has not "
        "been implemented. Audit sqli manually or write the finder."
    )
