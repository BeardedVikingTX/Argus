#!/usr/bin/env python3
"""
db.py — Argus bridge client
─────────────────────────────────────────────────────────────────────────────

Thin, reliable client for bug-bounty.beardedviking.org/api.php.

Design:
  • Every call is signed with HMAC-SHA256 (prevents tampering + replay)
  • Every call fails soft — if the bridge is down, the pipeline continues
  • Every call is retried twice with exponential backoff
  • Nothing that ends up in the database is required for the pipeline to work

If BRIDGE_ENABLED is False or the bridge is unreachable, all methods return
None and log a warning. The pipeline treats that as "no DB for this scan."
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.db")

# Load config defensively
try:
    import config as _cfg
    BRIDGE_ENABLED = getattr(_cfg, "BRIDGE_ENABLED", False)
    BRIDGE_URL     = getattr(_cfg, "BRIDGE_URL", "")
    BRIDGE_KEY     = getattr(_cfg, "BRIDGE_KEY", "")
    BRIDGE_TIMEOUT = getattr(_cfg, "BRIDGE_TIMEOUT", 30)
    BRIDGE_RETRIES = getattr(_cfg, "BRIDGE_RETRIES", 2)
except ImportError:
    BRIDGE_ENABLED = False
    BRIDGE_URL     = ""
    BRIDGE_KEY     = ""
    BRIDGE_TIMEOUT = 30
    BRIDGE_RETRIES = 2
    log.info("config.py not found — database features disabled")


class ArgusDB:
    """Client for the Argus PHP bridge."""

    def __init__(self, url: str = BRIDGE_URL, key: str = BRIDGE_KEY):
        self.url = url.rstrip("/")
        self.key = key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Argus-DB/1.0"})
        self.session.verify = True  # bridge uses valid TLS

    @property
    def available(self) -> bool:
        return BRIDGE_ENABLED and bool(self.url) and bool(self.key)

    # ── Core request ────────────────────────────────────────────────────────

    def _call(self, action: str, payload: dict) -> Optional[dict]:
        if not self.available:
            return None

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ts = str(int(time.time()))
        sig = hmac.new(
            self.key.encode("utf-8"),
            ts.encode("utf-8") + b"." + body,
            hashlib.sha256,
        ).hexdigest()

        headers = {
            "Content-Type":    "application/json",
            "X-Argus-Key":     self.key[:8],  # key ID prefix
            "X-Argus-Ts":      ts,
            "X-Argus-Sig":     sig,
        }

        for attempt in range(BRIDGE_RETRIES + 1):
            try:
                r = self.session.post(
                    f"{self.url}?action={action}",
                    data=body,
                    headers=headers,
                    timeout=BRIDGE_TIMEOUT,
                )
                if r.status_code == 200:
                    try:
                        return r.json()
                    except json.JSONDecodeError:
                        log.warning(f"bridge returned non-JSON for {action}")
                        return None
                if r.status_code == 401:
                    log.error(f"bridge auth failed — check BRIDGE_KEY")
                    return None
                if r.status_code == 429:
                    log.warning(f"bridge rate limit hit on {action} — backing off")
                    time.sleep(2 ** attempt)
                    continue
                log.warning(f"bridge {action} returned {r.status_code}")
                return None
            except requests.RequestException as e:
                if attempt < BRIDGE_RETRIES:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                log.warning(f"bridge {action} failed: {e}")
                return None
        return None

    # ── Public API ──────────────────────────────────────────────────────────

    def ping(self) -> bool:
        r = self._call("ping", {})
        return bool(r and r.get("ok"))

    def create_scan(self, scan_uuid: str, wildcards: list[str],
                    platform: str, pipeline: list[str]) -> Optional[int]:
        r = self._call("scan.create", {
            "scan_uuid":  scan_uuid,
            "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "wildcards":  wildcards,
            "platform":   platform,
            "pipeline":   pipeline,
        })
        return r.get("scan_id") if r and r.get("ok") else None

    def finish_scan(self, scan_uuid: str, stats: dict) -> bool:
        r = self._call("scan.finish", {
            "scan_uuid":   scan_uuid,
            "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "stats":       stats,
        })
        return bool(r and r.get("ok"))

    def save_stage(self, scan_id: int, stage: str, status: str,
                   duration_ms: int, artifacts: list[str],
                   stats: dict, error: Optional[str] = None) -> bool:
        r = self._call("stage.save", {
            "scan_id":        scan_id,
            "stage":          stage,
            "status":         status,
            "started_at":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "finished_at":    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "duration_ms":    duration_ms,
            "artifact_paths": artifacts,
            "stats":          stats,
            "error":          error,
        })
        return bool(r and r.get("ok"))

    def upsert_hosts(self, scan_id: int, hosts: list[dict]) -> Optional[int]:
        r = self._call("hosts.upsert", {"scan_id": scan_id, "hosts": hosts})
        return r.get("count") if r and r.get("ok") else None

    def upsert_endpoints(self, scan_id: int, endpoints: list[dict]) -> Optional[int]:
        r = self._call("endpoints.upsert", {"scan_id": scan_id, "endpoints": endpoints})
        return r.get("count") if r and r.get("ok") else None

    def upsert_subdomains(
        self, scan_id: int, subdomains: list[dict], chunk_size: int = 500,
    ) -> Optional[int]:
        """
        Upsert subdomains in chunks. Returns total count upserted, or None
        if the bridge is unavailable.

        Chunking matters: a scan on a large scope can produce 5,000+ subdomains.
        A single request with that payload would be slow to serialize and
        could hit PHP's post_max_size limit.
        """
        if not subdomains:
            return 0

        total = 0
        for i in range(0, len(subdomains), chunk_size):
            chunk = subdomains[i:i + chunk_size]
            r = self._call("subdomains.upsert", {
                "scan_id":    scan_id,
                "subdomains": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"subdomains.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_subdomains(
        self, scan_uuid: str, limit: int = 500, offset: int = 0,
        resolves: Optional[bool] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if resolves is not None:
            payload["resolves"] = resolves
        r = self._call("query.subdomains", payload)
        return r.get("subdomains") if r and r.get("ok") else None

    def upsert_live_hosts(
        self, scan_id: int, live_hosts: list[dict], chunk_size: int = 200,
    ) -> Optional[int]:
        """
        Upsert live hosts in chunks.

        Chunk size is smaller than subdomains because each row is much larger
        (TLS data, titles, geo). 200 rows × ~50KB payload ≈ 10MB, which is a
        comfortable margin under PHP's default post_max_size (8MB).
        Lower this to 100 if you see truncation on the server.
        """
        if not live_hosts:
            return 0

        total = 0
        for i in range(0, len(live_hosts), chunk_size):
            chunk = live_hosts[i:i + chunk_size]
            r = self._call("live_hosts.upsert", {
                "scan_id":    scan_id,
                "live_hosts": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"live_hosts.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_live_hosts(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        interesting: Optional[bool] = None, min_score: Optional[int] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if interesting is not None:
            payload["interesting"] = interesting
        if min_score is not None:
            payload["min_score"] = min_score
        r = self._call("query.live_hosts", payload)
        return r.get("live_hosts") if r and r.get("ok") else None

    def upsert_findings(self, scan_id: int, findings: list[dict]) -> Optional[int]:
        r = self._call("findings.upsert", {"scan_id": scan_id, "findings": findings})
        return r.get("count") if r and r.get("ok") else None

    def sync_oob(self, scan_id: int, tokens: list[str]) -> Optional[int]:
        r = self._call("oob.sync", {"scan_id": scan_id, "tokens": tokens})
        return r.get("count") if r and r.get("ok") else None

    def get_stats(self, scan_uuid: str) -> Optional[dict]:
        r = self._call("query.stats", {"scan_uuid": scan_uuid})
        return r.get("stats") if r and r.get("ok") else None


# ── Module-level singleton ──────────────────────────────────────────────────
DB = ArgusDB()
