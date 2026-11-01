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

    def upsert_dns_records(
        self, scan_id: int, dns_records: list[dict], chunk_size: int = 300,
    ) -> Optional[int]:
        """Upsert DNS records in chunks."""
        if not dns_records:
            return 0

        total = 0
        for i in range(0, len(dns_records), chunk_size):
            chunk = dns_records[i:i + chunk_size]
            r = self._call("dns_records.upsert", {
                "scan_id":     scan_id,
                "dns_records": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"dns_records.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_dns_records(
        self, scan_uuid: str, limit: int = 1000, offset: int = 0,
        resolves: Optional[bool] = None, takeover: Optional[bool] = None,
        exclude_wildcard: bool = False,
    ) -> Optional[list]:
        payload = {
            "scan_uuid":       scan_uuid,
            "limit":           limit,
            "offset":          offset,
            "exclude_wildcard": exclude_wildcard,
        }
        if resolves is not None:
            payload["resolves"] = resolves
        if takeover is not None:
            payload["takeover"] = takeover
        r = self._call("query.dns_records", payload)
        return r.get("dns_records") if r and r.get("ok") else None

    def upsert_js_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 200,
    ) -> Optional[int]:
        """
        Upsert JS findings in chunks.

        Smaller chunk size than subdomains because each row can carry up to
        16MB of endpoint text. 200 × 50KB ≈ 10MB per request, comfortably
        under PHP's default post_max_size (8MB) — but with margin.
        """
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("js_findings.upsert", {
                "scan_id":     scan_id,
                "js_findings": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"js_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_js_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        kind: Optional[str] = None, severity: Optional[str] = None,
        min_confidence: Optional[int] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if kind is not None:
            payload["kind"] = kind
        if severity is not None:
            payload["severity"] = severity
        if min_confidence is not None:
            payload["min_confidence"] = min_confidence
        r = self._call("query.js_findings", payload)
        return r.get("js_findings") if r and r.get("ok") else None

    def upsert_nmap_hosts(
        self, scan_id: int, hosts: list[dict], chunk_size: int = 100,
    ) -> Optional[dict]:
        """
        Upsert nmap hosts. Returns {'count': N, 'host_ids': {hash: id}} or None.
        """
        if not hosts:
            return {"count": 0, "host_ids": {}}

        total = 0
        all_host_ids: dict[str, int] = {}
        for i in range(0, len(hosts), chunk_size):
            chunk = hosts[i:i + chunk_size]
            r = self._call("nmap_hosts.upsert", {
                "scan_id":    scan_id,
                "nmap_hosts": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
                all_host_ids.update(r.get("host_ids", {}))
            else:
                log.warning(
                    f"nmap_hosts.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return {"count": total, "host_ids": all_host_ids}

    def upsert_nmap_ports(
        self, scan_id: int, ports: list[dict], chunk_size: int = 500,
    ) -> Optional[int]:
        """Upsert nmap ports in chunks."""
        if not ports:
            return 0

        total = 0
        for i in range(0, len(ports), chunk_size):
            chunk = ports[i:i + chunk_size]
            r = self._call("nmap_ports.upsert", {
                "scan_id":    scan_id,
                "nmap_ports": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"nmap_ports.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_nmap_hosts(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        interesting: bool = False, min_score: Optional[int] = None,
    ) -> Optional[list]:
        payload = {
            "scan_uuid": scan_uuid,
            "limit": limit,
            "offset": offset,
            "interesting": interesting,
        }
        if min_score is not None:
            payload["min_score"] = min_score
        r = self._call("query.nmap_hosts", payload)
        return r.get("nmap_hosts") if r and r.get("ok") else None

    def get_nmap_ports(
        self, scan_uuid: str, limit: int = 1000, offset: int = 0,
        port: Optional[int] = None, service: Optional[str] = None,
        flag: Optional[str] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if port is not None:
            payload["port"] = port
        if service is not None:
            payload["service"] = service
        if flag is not None:
            payload["flag"] = flag
        r = self._call("query.nmap_ports", payload)
        return r.get("nmap_ports") if r and r.get("ok") else None

    def upsert_nuclei_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 100,
    ) -> Optional[int]:
        """
        Upsert nuclei findings in chunks.

        Chunk size is small (100) because each finding can carry full
        request/response bodies — 100 × 100KB ≈ 10MB, just under PHP's
        default post_max_size.
        """
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("nuclei_findings.upsert", {
                "scan_id":         scan_id,
                "nuclei_findings": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"nuclei_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def save_nuclei_batch(
        self, scan_id: int, batch: dict,
    ) -> Optional[int]:
        """Record a nuclei batch execution (rate limit used, targets count, etc.)."""
        r = self._call("nuclei_batch.save", {
            "scan_id": scan_id,
            **batch,
        })
        return r.get("id") if r and r.get("ok") else None

    def get_nuclei_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        severity: Optional[str] = None, template_id: Optional[str] = None,
        scheme: Optional[str] = None, min_cvss: Optional[float] = None,
        has_cve: bool = False,
    ) -> Optional[list]:
        payload = {
            "scan_uuid": scan_uuid,
            "limit":     limit,
            "offset":    offset,
            "has_cve":   has_cve,
        }
        if severity is not None:
            payload["severity"] = severity
        if template_id is not None:
            payload["template_id"] = template_id
        if scheme is not None:
            payload["scheme"] = scheme
        if min_cvss is not None:
            payload["min_cvss"] = min_cvss
        r = self._call("query.nuclei_findings", payload)
        return r.get("nuclei_findings") if r and r.get("ok") else None

    def get_nuclei_batches(self, scan_uuid: str) -> Optional[list]:
        r = self._call("query.nuclei_batches", {"scan_uuid": scan_uuid})
        return r.get("nuclei_batches") if r and r.get("ok") else None

    def upsert_param_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 300,
    ) -> Optional[int]:
        """Upsert parameter findings in chunks."""
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("param_findings.upsert", {
                "scan_id":        scan_id,
                "param_findings": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"param_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_param_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        min_confidence: Optional[int] = None,
        vuln_class: Optional[str] = None,
        method: Optional[str] = None,
        oracle: Optional[str] = None,
        only_hidden: bool = False,
        min_oracles: Optional[int] = None,
    ) -> Optional[list]:
        payload = {
            "scan_uuid":   scan_uuid,
            "limit":       limit,
            "offset":      offset,
            "only_hidden": only_hidden,
        }
        if min_confidence is not None:
            payload["min_confidence"] = min_confidence
        if vuln_class is not None:
            payload["vuln_class"] = vuln_class
        if method is not None:
            payload["method"] = method
        if oracle is not None:
            payload["oracle"] = oracle
        if min_oracles is not None:
            payload["min_oracles"] = min_oracles
        r = self._call("query.param_findings", payload)
        return r.get("param_findings") if r and r.get("ok") else None

    def upsert_takeover_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 500,
    ) -> Optional[int]:
        """Upsert takeover findings in chunks."""
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("takeover_findings.upsert", {
                "scan_id":            scan_id,
                "takeover_findings":  chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"takeover_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_takeover_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        status: Optional[str] = None, service: Optional[str] = None,
        vulnerable_only: bool = False, dangling_only: bool = False,
        shared_only: bool = False,
    ) -> Optional[list]:
        payload = {
            "scan_uuid":        scan_uuid,
            "limit":            limit,
            "offset":           offset,
            "vulnerable_only":  vulnerable_only,
            "dangling_only":    dangling_only,
            "shared_only":      shared_only,
        }
        if status is not None:
            payload["status"] = status
        if service is not None:
            payload["service"] = service
        r = self._call("query.takeover_findings", payload)
        return r.get("takeover_findings") if r and r.get("ok") else None

    def upsert_url_categorize(
        self, scan_id: int, entries: list[dict], chunk_size: int = 500,
    ) -> Optional[int]:
        """Upsert per-URL category data in chunks."""
        if not entries:
            return 0

        total = 0
        for i in range(0, len(entries), chunk_size):
            chunk = entries[i:i + chunk_size]
            r = self._call("url_categorize.upsert", {
                "scan_id":        scan_id,
                "url_categorize": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"url_categorize.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_url_categorize(
        self, scan_uuid: str, limit: int = 1000, offset: int = 0,
        category: Optional[str] = None, min_weight: Optional[int] = None,
        min_categories: Optional[int] = None, priority_only: bool = False,
        param_contains: Optional[str] = None,
    ) -> Optional[list]:
        payload = {
            "scan_uuid":     scan_uuid,
            "limit":         limit,
            "offset":        offset,
            "priority_only": priority_only,
        }
        if category is not None:
            payload["category"] = category
        if min_weight is not None:
            payload["min_weight"] = min_weight
        if min_categories is not None:
            payload["min_categories"] = min_categories
        if param_contains is not None:
            payload["param_contains"] = param_contains
        r = self._call("query.url_categorize", payload)
        return r.get("url_categorize") if r and r.get("ok") else None

    def upsert_urls(
        self, scan_id: int, urls: list[dict], chunk_size: int = 300,
    ) -> Optional[int]:
        """
        Upsert harvested URLs in chunks.

        URLs can number in the tens of thousands per scan. 300/request keeps
        each payload under 500KB while minimizing round-trips.
        """
        if not urls:
            return 0

        total = 0
        for i in range(0, len(urls), chunk_size):
            chunk = urls[i:i + chunk_size]
            r = self._call("urls.upsert", {"scan_id": scan_id, "urls": chunk})
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"urls.upsert chunk failed ({len(chunk)} entries, offset {i})"
                )
        return total

    def get_urls(
        self, scan_uuid: str, limit: int = 1000, offset: int = 0,
        interesting_only: bool = False, form_only: bool = False,
        params_only: bool = False, js_only: bool = False,
        alive_only: bool = False, source: Optional[str] = None,
        host: Optional[str] = None,
    ) -> Optional[list]:
        payload = {
            "scan_uuid":       scan_uuid,
            "limit":           limit,
            "offset":          offset,
            "interesting_only": interesting_only,
            "form_only":       form_only,
            "params_only":     params_only,
            "js_only":         js_only,
            "alive_only":      alive_only,
        }
        if source is not None:
            payload["source"] = source
        if host is not None:
            payload["host"] = host
        r = self._call("query.urls", payload)
        return r.get("urls") if r and r.get("ok") else None

    def upsert_triage_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 200,
    ) -> Optional[int]:
        """Upsert triaged findings in chunks."""
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("triage_findings.upsert", {
                "scan_id":           scan_id,
                "triage_findings":   chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"triage_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_triage_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        min_score: Optional[float] = None, severity: Optional[str] = None,
        finding_status: Optional[str] = None, kind: Optional[str] = None,
        host: Optional[str] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if min_score is not None:
            payload["min_score"] = min_score
        if severity is not None:
            payload["severity"] = severity
        if finding_status is not None:
            payload["finding_status"] = finding_status
        if kind is not None:
            payload["kind"] = kind
        if host is not None:
            payload["host"] = host
        r = self._call("query.triage_findings", payload)
        return r.get("triage_findings") if r and r.get("ok") else None

    def get_triage_history(self, finding_hash: str) -> Optional[list]:
        r = self._call("query.triage_history", {"finding_hash": finding_hash})
        return r.get("history") if r and r.get("ok") else None

    def upsert_auth_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 200,
    ) -> Optional[int]:
        """Upsert auth findings in chunks."""
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("auth_findings.upsert", {
                "scan_id":        scan_id,
                "auth_findings":  chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"auth_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_auth_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        severity: Optional[str] = None, category: Optional[str] = None,
        vuln_type: Optional[str] = None, host: Optional[str] = None,
        min_confidence: Optional[int] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if severity is not None:
            payload["severity"] = severity
        if category is not None:
            payload["category"] = category
        if vuln_type is not None:
            payload["vuln_type"] = vuln_type
        if host is not None:
            payload["host"] = host
        if min_confidence is not None:
            payload["min_confidence"] = min_confidence
        r = self._call("query.auth_findings", payload)
        return r.get("auth_findings") if r and r.get("ok") else None

    def upsert_cache_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 200,
    ) -> Optional[int]:
        """Upsert cache findings in chunks."""
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("cache_findings.upsert", {
                "scan_id":        scan_id,
                "cache_findings": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"cache_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_cache_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        severity: Optional[str] = None, category: Optional[str] = None,
        vuln_type: Optional[str] = None, host: Optional[str] = None,
        confirmed_only: bool = False, min_confidence: Optional[int] = None,
    ) -> Optional[list]:
        payload = {
            "scan_uuid":      scan_uuid,
            "limit":          limit,
            "offset":         offset,
            "confirmed_only": confirmed_only,
        }
        if severity is not None:
            payload["severity"] = severity
        if category is not None:
            payload["category"] = category
        if vuln_type is not None:
            payload["vuln_type"] = vuln_type
        if host is not None:
            payload["host"] = host
        if min_confidence is not None:
            payload["min_confidence"] = min_confidence
        r = self._call("query.cache_findings", payload)
        return r.get("cache_findings") if r and r.get("ok") else None

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

    def upsert_site_pages(
        self, scan_id: int, site_pages: list[dict], chunk_size: int = 100,
    ) -> Optional[int]:
        """
        Upsert crawled pages in chunks.

        Chunk size is smaller than live_hosts because the forms/links arrays
        can be large. 100 pages × ~30KB payload ≈ 3MB, well under the
        default post_max_size.
        """
        if not site_pages:
            return 0

        total = 0
        for i in range(0, len(site_pages), chunk_size):
            chunk = site_pages[i:i + chunk_size]
            r = self._call("site_pages.upsert", {
                "scan_id":    scan_id,
                "site_pages": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"site_pages.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def upsert_content_fuzz(
        self, scan_id: int, findings: list[dict], chunk_size: int = 300,
    ) -> Optional[int]:
        """Upsert content fuzz results in chunks."""
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("content_fuzz.upsert", {
                "scan_id":      scan_id,
                "content_fuzz": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"content_fuzz.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_content_fuzz(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        min_confidence: Optional[int] = None, source_tool: Optional[str] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if min_confidence is not None:
            payload["min_confidence"] = min_confidence
        if source_tool is not None:
            payload["source_tool"] = source_tool
        r = self._call("query.content_fuzz", payload)
        return r.get("content_fuzz") if r and r.get("ok") else None

    def upsert_cors_findings(
        self, scan_id: int, findings: list[dict], chunk_size: int = 300,
    ) -> Optional[int]:
        """Upsert CORS findings in chunks."""
        if not findings:
            return 0

        total = 0
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            r = self._call("cors_findings.upsert", {
                "scan_id":       scan_id,
                "cors_findings": chunk,
            })
            if r and r.get("ok"):
                total += r.get("count", 0)
            else:
                log.warning(
                    f"cors_findings.upsert chunk failed "
                    f"({len(chunk)} entries, offset {i})"
                )
        return total

    def get_cors_findings(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        min_score: Optional[int] = None, severity: Optional[str] = None,
        acac: Optional[bool] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if min_score is not None:
            payload["min_score"] = min_score
        if severity is not None:
            payload["severity"] = severity
        if acac is not None:
            payload["acac"] = acac
        r = self._call("query.cors_findings", payload)
        return r.get("cors_findings") if r and r.get("ok") else None

    def get_site_pages(
        self, scan_uuid: str, limit: int = 100, offset: int = 0,
        page_kind: Optional[str] = None, is_auth: Optional[bool] = None,
    ) -> Optional[list]:
        payload = {"scan_uuid": scan_uuid, "limit": limit, "offset": offset}
        if page_kind is not None:
            payload["page_kind"] = page_kind
        if is_auth is not None:
            payload["is_auth"] = is_auth
        r = self._call("query.site_pages", payload)
        return r.get("site_pages") if r and r.get("ok") else None

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
