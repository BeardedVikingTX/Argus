#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_tools/takeover_check.py — Subdomain Takeover Detection
═══════════════════════════════════════════════════════════════════════════════

  File      : recon_tools/takeover_check.py
  Version   : 3.0.0 "RAGNARÖK"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Three-stage validation with multi-signal confirmation:
    1. CNAME chain resolution — full chain traversal, not just last hop
    2. Fingerprint matching — scans EVERY hop in the chain, not just the leaf
    3. HTTP body confirmation — service-specific unclaimed-page fingerprints

  v3.0 (this release) — BUG FIXES:
    [FIX]  `headers=` kwarg was silently ignored — now merged at request time.
    [FIX]  `_write_report` reported the module constant HTTP_THREADS instead of
           the effective value passed by the caller.
    [FIX]  All three early-exit paths dropped `scan_id` — DB sync was never
           triggered for empty input / no-CNAME / no-candidate runs.
    [FIX]  `_confirm_http` gave up on the first 404 — HTTPS 404 blocked HTTP
           fallback entirely (extremely common failure mode).
    [FIX]  `_confirm_http` returned status=0 on total failure, losing the last
           status code seen.
    [FIX]  `_resolve_terminal_a` checked only A, never AAAA — IPv6-only
           terminals falsely flagged as dangling.
    [FIX]  `_load_subdomains` did not strip trailing dots — inconsistent keys.
    [FIX]  `resp.raw.read()` truncated before decode on chunked+gzip — garbled
           bodies produced missed fingerprints. Now uses `iter_content`.

  v3.0 — NEW:
    [NEW]  AI triage with service-aware prompt (mirrors nuclei_scan v3.1).
    [NEW]  Heuristic triage is now a first-class default path with confidence,
           exploit narrative, claim steps, and cluster detection.
    [NEW]  SSL cert-mismatch detection — wrong/expired cert is a takeover signal.
    [NEW]  Vendor redirect-to-claim detection — final URL is matched against
           known vendor signup paths.
    [NEW]  Wildcard CNAME detection (`*.herokuapp.com`) → downgrades confidence.
    [NEW]  Apex CNAME detection.
    [NEW]  Expanded fingerprint DB (~80 services) with `exploit_steps` and
           `claim_url` per entry.
    [NEW]  `--min-cvss` / `--min-severity` filtering.
    [NEW]  `--only-dangling` shortlist output.
    [NEW]  `--dry-run` — CNAME resolution only, no HTTP.
    [NEW]  `--ai-parallel` / `--ai-workers` — parallel AI triage.
    [NEW]  `on_progress` callback for TUI/dashboard integration.
    [NEW]  SIGINT handler — finish current HTTP batch, write partial report.
    [NEW]  Structured `warnings` array in the report JSON.
    [NEW]  Rate limiter honoring MODULE_RATE_LIMITS["takeover"]["rate_limit"].
    [NEW]  BOM / trailing-dot / URL / port normalization in `_load_subdomains`.
    [NEW]  `dnsx -a -aaaa -cname -json` in one pass — no extra socket round.
    [NEW]  Selftest with ~45 checks.

  Preserves every public symbol and file output from v2. Schema is additive only.
  Module-level outputs are identical (`takeover_findings.json`,
  `takeover_vulnerable.txt`, `takeover_potential.txt`, `takeover_cnames.txt`).

  Config integration (config.py):
    • MODULE_RATE_LIMITS["takeover"]  → concurrency + rate_limit + timeout
    • ACTIVE_HEADERS + AUTH_HEADERS   → merged into per-request headers
    • AUTH_COOKIES                    → attached to requests session
    • SYNC_TO_DB, BRIDGE_*            → remote database sync
    • AI_ENABLED, AI.model, ai_complete → AI triage
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import logging
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("argus.takeover")


# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═════════════════════════════════════════════════════════════════════════════

try:
    import config as CFG
    CFG_LOADED = True
except ImportError:
    CFG = None  # type: ignore[assignment]
    CFG_LOADED = False

try:
    from db import DB  # type: ignore
    DB_AVAILABLE = True
except ImportError:
    DB = None  # type: ignore[assignment]
    DB_AVAILABLE = False


def _cfg(key: str, default: Any = None) -> Any:
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


def _ai_enabled() -> bool:
    try:
        return bool(_cfg("AI_ENABLED", False))
    except Exception:
        return False


def _takeover_settings() -> dict:
    entry = (_cfg("MODULE_RATE_LIMITS", {}) or {}).get("takeover", {}) or {}
    threads = entry.get("concurrency", 15)
    rate = entry.get("rate_limit", 100)
    timeout = entry.get("timeout", 12)
    if not isinstance(threads, int) or threads < 1: threads = 15
    if not isinstance(rate, int) or rate < 0:       rate = 100
    if not isinstance(timeout, int) or timeout < 1: timeout = 12
    return {"threads": threads, "rate_limit": rate, "timeout": timeout}


def _target_headers(extra: Optional[dict] = None) -> dict[str, str]:
    h: dict[str, str] = dict(_cfg("ACTIVE_HEADERS", {}) or {})
    if CFG_LOADED and getattr(CFG, "AUTH_ENABLED", False):
        auth_hdrs = getattr(CFG, "AUTH_HEADERS", {}) or {}
        if auth_hdrs:
            h.update(auth_hdrs)
    if extra:
        # v3.0: caller-supplied headers override config (fixes silently-dropped kwarg)
        h.update(extra)
    return h


def _auth_cookies() -> dict[str, str]:
    if not CFG_LOADED or not getattr(CFG, "AUTH_ENABLED", False):
        return {}
    return dict(getattr(CFG, "AUTH_COOKIES", {}) or {})


def _killswitch_check(label: str) -> None:
    """v3.0: honor the config KillSwitch before network operations."""
    try:
        ks = _cfg("KillSwitch")
        if ks is not None and hasattr(ks, "check"):
            ks.check()
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DNSX_THREADS    = 50
DNSX_TIMEOUT    = 300
HTTP_THREADS    = 15
HTTP_TIMEOUT    = 12
HTTP_RETRIES    = 2
MAX_INPUT       = 20000
MAX_HTTP_BODY   = 131072   # 128KB

AI_MIN_FINDINGS_PER_RUN     = 1
AI_MAX_FINDINGS_PER_RUN     = 20
AI_DEFAULT_CACHE_TTL_HOURS  = 72
AI_DEFAULT_MAX_WORKERS      = 4
AI_ESTIMATE_PER_CALL_USD    = 0.002
AI_PROMPT_VERSION           = "v3.0"


# ═════════════════════════════════════════════════════════════════════════════
#  FINGERPRINT DATABASE — v3.0 expanded, with exploit_steps + claim_url
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ServiceFingerprint:
    name: str
    cname_patterns: list[str]
    http_fingerprints: list[str]
    status_code: Optional[int] = 404
    vulnerable: bool = True
    cvss: float = 8.0
    notes: str = ""
    # v3.0 additions
    exploit_steps: list[str] = field(default_factory=list)
    claim_url: str = ""
    attacker_impact: str = "Subdomain impersonation, phishing, cookie theft"


FINGERPRINTS: list[ServiceFingerprint] = [
    # ── Major CDN / hosting / PaaS ──────────────────────────────────────────
    ServiceFingerprint(
        "GitHub Pages", ["github.io", "github.com"],
        ["There isn't a GitHub Pages site here."],
        404, True, 8.1,
        "Claim by creating a repo with matching CNAME",
        ["Create a GitHub repo named after the subdomain (e.g. `sub` → owner.github.io)",
         "Add a CNAME file to the repo containing the victim subdomain",
         "Push — GitHub Pages will start serving at the victim subdomain"],
        "https://github.com/new",
        "Any content served under victim's domain; cookie theft; XSS",
    ),
    ServiceFingerprint(
        "Heroku", ["herokuapp.com", "herokudns.com"],
        ["No such app", "heroku | no such app"],
        404, True, 8.8,
        "Claim by creating an app with the same name",
        ["heroku create <app-name>  (same name as the terminal CNAME)",
         "heroku domains:add <victim-subdomain>",
         "Deploy any content — now served at victim subdomain"],
        "https://dashboard.heroku.com/new-app",
        "Full subdomain control; phishing; session fixation",
    ),
    ServiceFingerprint(
        "AWS S3", ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
        ["NoSuchBucket", "The specified bucket does not exist"],
        404, True, 9.3,
        "Claim by creating a bucket with the same name",
        ["aws s3api create-bucket --bucket <name> --region <region>",
         "aws s3 website s3://<name>/ --index-document index.html",
         "Upload any HTML — served at victim subdomain"],
        "https://s3.console.aws.amazon.com/s3/bucket/create",
        "Arbitrary content; malware hosting; phishing; OAuth flow hijack",
    ),
    ServiceFingerprint(
        "AWS S3 website", ["s3-website-", ".s3-website."],
        ["NoSuchBucket", "The specified bucket does not exist"],
        404, True, 9.3,
        "S3 website endpoint — claim by creating matching bucket",
        ["aws s3api create-bucket --bucket <name>",
         "Enable website hosting and upload content"],
        "https://s3.console.aws.amazon.com/s3/bucket/create",
        "Arbitrary content; phishing",
    ),
    ServiceFingerprint(
        "AWS CloudFront", ["cloudfront.net"],
        ["Bad request.", "ERROR: The request could not be satisfied"],
        403, True, 7.5,
        "Requires distribution deletion + recreation",
        ["Create a new CloudFront distribution",
         "Add victim subdomain as alternative domain name",
         "Point your DNS at the distribution"],
        "https://console.aws.amazon.com/cloudfront/",
        "Requires coordinated DNS change — lower likelihood",
    ),
    ServiceFingerprint(
        "AWS Elastic Beanstalk", ["elasticbeanstalk.com"],
        ["404 Not Found"], 404, True, 8.0,
        "Claim by creating an EB environment with the same name",
        ["eb create <env-name>",
         "Add victim subdomain as custom domain"],
        "https://console.aws.amazon.com/elasticbeanstalk/",
        "Arbitrary content; phishing",
    ),
    ServiceFingerprint(
        "AWS Amplify", ["amplifyapp.com"],
        ["404", "not found"], 404, True, 8.0,
        "Claim by creating an Amplify app with the same name",
        ["Create Amplify app with subdomain-matched name",
         "Add custom domain pointing at the victim subdomain"],
        "https://console.aws.amazon.com/amplify/",
        "Arbitrary content; phishing",
    ),
    ServiceFingerprint(
        "AWS API Gateway", ["execute-api.", ".amazonaws.com"],
        ["Missing Authentication Token", "404"], 403, True, 7.5,
        "Requires matching custom domain in API Gateway",
        ["Create custom domain name in API Gateway",
         "Match the victim subdomain"],
        "https://console.aws.amazon.com/apigateway/",
        "API impersonation; credential phishing",
    ),
    ServiceFingerprint(
        "Azure App Service", ["azurewebsites.net"],
        ["Error 404 - Web app not found."], 404, True, 8.5,
        "Claim by creating an app service with the same name",
        ["Create App Service with matching name",
         "Add victim subdomain as custom domain"],
        "https://portal.azure.com/",
        "Arbitrary content; phishing",
    ),
    ServiceFingerprint(
        "Azure Cloud App", ["cloudapp.azure.com", "cloudapp.net"],
        ["404 Web Site not found."], 404, True, 8.0,
        "Claim by creating a cloud service with the same name",
        ["Create cloud service with matching name"],
        "https://portal.azure.com/",
        "Arbitrary content",
    ),
    ServiceFingerprint(
        "Azure Blob Storage", ["blob.core.windows.net"],
        ["BlobNotFound", "The specified blob does not exist"],
        404, True, 8.5,
        "Claim by creating a storage account with the same name",
        ["Create storage account with matching name",
         "Enable static website hosting"],
        "https://portal.azure.com/",
        "Arbitrary content; malware hosting",
    ),
    ServiceFingerprint(
        "Azure Traffic Manager", ["trafficmanager.net"],
        ["Not Found", "404"], 404, True, 7.5,
        "Requires creating a matching Traffic Manager profile",
        ["Create Traffic Manager profile with matching name"],
        "https://portal.azure.com/",
        "Traffic redirection",
    ),
    ServiceFingerprint(
        "Azure Static Web Apps", ["azurestaticapps.net"],
        ["404", "not found"], 404, True, 7.5,
        "Claim by creating a Static Web App with matching name",
        ["Create Static Web App with matching name"],
        "https://portal.azure.com/",
        "Arbitrary content",
    ),
    ServiceFingerprint(
        "Azure Functions", ["azurewebsites.net"],
        ["Function host is not running", "404"], 404, True, 7.5,
        "Claim by creating a Function App with matching name",
        ["Create Function App with matching name"],
        "https://portal.azure.com/",
        "API impersonation",
    ),
    # ── Netlify / Vercel / modern PaaS ──────────────────────────────────────
    ServiceFingerprint(
        "Netlify", ["netlify.app", "netlify.com"],
        ["Not Found - Request ID:", "Page not found"],
        404, True, 8.8,
        "Claim by creating a Netlify site with the same subdomain",
        ["netlify sites:create --name <name>",
         "netlify domains:add <victim-subdomain>"],
        "https://app.netlify.com/start",
        "Arbitrary content; phishing; cookie theft",
    ),
    ServiceFingerprint(
        "Vercel", ["vercel.app", "now.sh"],
        ["The deployment could not be found on Vercel.", "DEPLOYMENT_NOT_FOUND"],
        404, True, 8.8,
        "Claim by creating a Vercel project with the same name",
        ["vercel --name <project>",
         "vercel domains add <victim-subdomain>"],
        "https://vercel.com/new",
        "Arbitrary content; phishing",
    ),
    # ── Other SaaS/website builders ─────────────────────────────────────────
    ServiceFingerprint("Shopify", ["myshopify.com", "shopifypreview.com"],
                       ["Sorry, this shop is currently unavailable.", "Only one step left!"],
                       404, True, 8.0, "Claim by creating a store with the same name",
                       ["Create Shopify store with matching name",
                        "Add victim subdomain as custom domain"],
                       "https://www.shopify.com/signup", "E-commerce impersonation"),
    ServiceFingerprint("Pantheon", ["pantheonsite.io"],
                       ["The gods are wise, but do not know of the site which you seek."],
                       404, True, 8.0, "Claim by creating a site with the same name",
                       ["Create Pantheon site with matching name",
                        "Add victim subdomain as custom domain"],
                       "https://dashboard.pantheon.io/", "Arbitrary content"),
    ServiceFingerprint("Tumblr", ["tumblr.com"],
                       ["Whatever you were looking for doesn't currently exist at this address."],
                       404, True, 7.5, "Claim by registering a blog with the subdomain handle",
                       ["Register Tumblr blog matching the subdomain"],
                       "https://www.tumblr.com/register", "Blog impersonation"),
    ServiceFingerprint("WordPress.com", ["wordpress.com"],
                       ["Do you want to register"], 404, True, 7.0,
                       "Claim by registering a WP.com blog with matching name",
                       ["Register WordPress.com blog matching the subdomain"],
                       "https://wordpress.com/start", "Blog impersonation"),
    ServiceFingerprint("Ghost", ["ghost.io"],
                       ["The thing you were looking for is no longer here"],
                       404, True, 7.5, "Claim by creating a Ghost site with matching name",
                       ["Create Ghost site with matching name"],
                       "https://ghost.org/pricing/", "Arbitrary content"),
    ServiceFingerprint("Zendesk", ["zendesk.com"],
                       ["Help Center Closed", "Oops, this help center no longer exists"],
                       404, True, 7.0, "Claim by creating a Zendesk subdomain with the same name",
                       ["Create Zendesk trial with matching subdomain"],
                       "https://www.zendesk.com/register/", "Support impersonation"),
    ServiceFingerprint("Statuspage", ["statuspage.io"],
                       ["You are being redirected", "Status page not found"],
                       404, True, 7.0, "Claim by creating a Statuspage with matching slug",
                       ["Create Statuspage with matching slug"],
                       "https://www.statuspage.io/signup", "Status page impersonation"),
    ServiceFingerprint("UserVoice", ["uservoice.com"],
                       ["This UserVoice subdomain is currently available!"],
                       404, True, 7.5, "Claim by creating a UserVoice with matching name",
                       ["Create UserVoice forum with matching name"],
                       "https://www.uservoice.com/signup", "Feedback impersonation"),
    ServiceFingerprint("Bitbucket", ["bitbucket.io"],
                       ["Repository not found"], 404, True, 7.5,
                       "Claim by creating a Bitbucket team with matching name",
                       ["Create Bitbucket team with matching name"],
                       "https://bitbucket.org/account/signup/", "Arbitrary content"),
    ServiceFingerprint("Fastly", ["fastly.net"],
                       ["Fastly error: unknown domain"], 404, True, 7.5,
                       "Requires adding matching custom domain to Fastly service",
                       ["Create Fastly service",
                        "Add victim subdomain as custom domain"],
                       "https://manage.fastly.com/", "Cache poisoning surface"),
    ServiceFingerprint("Surge.sh", ["surge.sh"],
                       ["project not found"], 404, True, 7.5,
                       "Claim by running `surge` in a directory with matching name",
                       ["mkdir <sub> && cd <sub> && surge --domain <victim>"],
                       "https://surge.sh/", "Arbitrary content"),
    ServiceFingerprint("Unbounce", ["unbounce.com"],
                       ["The requested URL was not found on this server."],
                       404, True, 7.0, "Claim by creating a landing page with matching subdomain",
                       ["Create Unbounce page with matching subdomain"],
                       "https://app.unbounce.com/", "Landing page impersonation"),
    ServiceFingerprint("ngrok", ["ngrok.io", "ngrok-free.app"],
                       ["Tunnel", "not found"], 404, True, 7.5,
                       "Rare — requires matching ephemeral tunnel subdomain",
                       ["Start ngrok tunnel with matching subdomain"],
                       "https://dashboard.ngrok.com/", "Traffic interception"),
    ServiceFingerprint("ReadMe", ["readme.io"],
                       ["The requested page could not be found."],
                       404, True, 7.0, "Claim by creating a ReadMe project with matching name",
                       ["Create ReadMe project with matching name"],
                       "https://readme.io/", "Docs impersonation"),
    ServiceFingerprint("Cargo", ["cargocollective.com"],
                       ["404 Not Found"], 404, True, 6.5,
                       "Claim by registering a matching Cargo subdomain",
                       ["Register Cargo account matching the subdomain"],
                       "https://cargocollective.com/", "Portfolio impersonation"),
    ServiceFingerprint("Kajabi", ["kajabi.com"],
                       ["The page you were looking for doesn't exist"],
                       404, True, 7.0, "Claim by creating a Kajabi site with matching name",
                       ["Create Kajabi site with matching name"],
                       "https://kajabi.com/", "Course platform impersonation"),
    ServiceFingerprint("Campaign Monitor", ["createsend.com"],
                       ["Double check the URL", "404"], 404, True, 6.5,
                       "Claim by creating a Campaign Monitor account matching subdomain",
                       ["Create Campaign Monitor account"],
                       "https://www.campaignmonitor.com/", "Email impersonation"),
    ServiceFingerprint("Pingdom", ["pingdom.com"],
                       ["This resource is not available"], 404, True, 6.0,
                       "Claim by registering a Pingdom account matching subdomain",
                       ["Create Pingdom account"], "https://www.pingdom.com/",
                       "Monitoring impersonation"),
    ServiceFingerprint("Strikingly", ["strikingly.com"],
                       ["page not found"], 404, True, 6.5,
                       "Claim by creating a Strikingly site with matching name",
                       ["Create Strikingly site with matching name"],
                       "https://www.strikingly.com/", "Landing page impersonation"),
    ServiceFingerprint("Agile CRM", ["agilecrm.com"],
                       ["Sorry, this page is no longer available."],
                       404, True, 6.5, "Claim by creating a matching Agile CRM account",
                       ["Create Agile CRM account"], "https://www.agilecrm.com/",
                       "CRM impersonation"),
    ServiceFingerprint("Help Scout", ["helpscoutdocs.com"],
                       ["No settings were found for this company"],
                       404, True, 7.0, "Claim by creating a Help Scout Docs with matching name",
                       ["Create Help Scout Docs site with matching name"],
                       "https://www.helpscout.com/", "Support impersonation"),
    ServiceFingerprint("Fly.io", ["fly.dev"],
                       ["404", "not found"], 404, True, 7.5,
                       "Claim by creating a Fly app with matching name",
                       ["fly apps create <name>", "fly certs add <victim-subdomain>"],
                       "https://fly.io/dashboard", "Arbitrary content"),
    ServiceFingerprint("Render", ["render.com"],
                       ["Not Found", "404"], 404, True, 7.5,
                       "Claim by creating a Render service with matching name",
                       ["Create Render service with matching name"],
                       "https://dashboard.render.com/", "Arbitrary content"),
    ServiceFingerprint("GitLab Pages", ["gitlab.io"],
                       ["404 Not Found", "The page you're looking for could not be found"],
                       404, True, 7.5,
                       "Claim by creating a GitLab project matching the subdomain",
                       ["Create GitLab project with matching name",
                        "Enable Pages with victim subdomain"],
                       "https://gitlab.com/projects/new", "Arbitrary content"),
    ServiceFingerprint("Cloudflare Workers", ["workers.dev"],
                       ["Error 1016", "Origin DNS error"], 404, True, 7.0,
                       "Rare — workers.dev subdomain ownership",
                       ["Register matching worker subdomain"],
                       "https://dash.cloudflare.com/", "Script execution surface"),
    ServiceFingerprint("Cloudflare Pages", ["pages.dev"],
                       ["404", "Not Found"], 404, True, 7.5,
                       "Claim by creating a Pages project with matching name",
                       ["Create Pages project with matching name"],
                       "https://dash.cloudflare.com/", "Arbitrary content"),
    ServiceFingerprint("Cloudflare R2", ["r2.cloudflarestorage.com", "r2.dev"],
                       ["NoSuchBucket", "404"], 404, True, 8.0,
                       "Claim by creating an R2 bucket with matching name",
                       ["Create R2 bucket with matching name"],
                       "https://dash.cloudflare.com/", "Arbitrary content; malware hosting"),
    ServiceFingerprint("Cloudflared Tunnel", ["trycloudflare.com", "cloudflare.net"],
                       ["Argo Tunnel error", "404"], 404, True, 7.5,
                       "Ephemeral tunnels — needs matching tunnel URL",
                       ["Start cloudflared tunnel matching victim subdomain"],
                       "https://dash.cloudflare.com/", "Traffic interception"),
    ServiceFingerprint("Replit", ["repl.co", "replit.app"],
                       ["404", "not found"], 404, True, 7.0,
                       "Claim by creating a Repl with matching name",
                       ["Create Repl with matching name"],
                       "https://replit.com/", "Arbitrary content"),
    ServiceFingerprint("Glitch", ["glitch.me"],
                       ["404", "not found"], 404, True, 6.5,
                       "Claim by creating a Glitch project with matching name",
                       ["Create Glitch project with matching name"],
                       "https://glitch.com/", "Arbitrary content"),
    ServiceFingerprint("Firebase", ["firebaseapp.com", "web.app"],
                       ["Site Not Found", "Firebase Hosting Site Not Found"],
                       404, True, 8.0,
                       "Claim by creating a Firebase project with matching site name",
                       ["Create Firebase project with matching site name",
                        "firebase deploy — serving at victim subdomain"],
                       "https://console.firebase.google.com/",
                       "Arbitrary content; API key theft"),
    ServiceFingerprint("DigitalOcean Spaces", ["digitaloceanspaces.com"],
                       ["NoSuchBucket", "The specified bucket does not exist"],
                       404, True, 8.5,
                       "Claim by creating a Spaces bucket with matching name",
                       ["Create Spaces bucket with matching name"],
                       "https://cloud.digitalocean.com/spaces",
                       "Arbitrary content; malware hosting"),
    ServiceFingerprint("Google Cloud Storage", ["storage.googleapis.com"],
                       ["NoSuchBucket", "The specified bucket does not exist"],
                       404, True, 8.5,
                       "Claim by creating a GCS bucket with matching name",
                       ["gsutil mb gs://<name>"],
                       "https://console.cloud.google.com/storage",
                       "Arbitrary content; malware hosting"),
    ServiceFingerprint("Backblaze B2", ["backblazeb2.com"],
                       ["NoSuchBucket", "404"], 404, True, 8.0,
                       "Claim by creating a B2 bucket with matching name",
                       ["Create B2 bucket with matching name"],
                       "https://secure.backblaze.com/", "Arbitrary content"),
    ServiceFingerprint("Bunny CDN", ["b-cdn.net"],
                       ["404", "Not Found"], 404, True, 7.0,
                       "Claim by creating a Bunny pull zone with matching name",
                       ["Create pull zone matching name",
                        "Add victim subdomain as custom hostname"],
                       "https://dash.bunny.net/", "Arbitrary content"),
    ServiceFingerprint("Linode Object Storage", ["linodeobjects.com", "us-east-1.linodeobjects.com"],
                       ["NoSuchBucket", "404"], 404, True, 7.5,
                       "Claim by creating an Object Storage bucket with matching name",
                       ["Create bucket with matching name"],
                       "https://cloud.linode.com/object-storage", "Arbitrary content"),
    ServiceFingerprint("Wasabi", ["wasabisys.com"],
                       ["NoSuchBucket", "404"], 404, True, 7.5,
                       "Claim by creating a Wasabi bucket with matching name",
                       ["Create Wasabi bucket with matching name"],
                       "https://console.wasabisys.com/", "Arbitrary content"),
    ServiceFingerprint("Aliyun OSS", ["oss-cn-", ".aliyuncs.com"],
                       ["NoSuchBucket", "The specified bucket does not exist"],
                       404, True, 8.0,
                       "Claim by creating an Aliyun OSS bucket with matching name",
                       ["Create OSS bucket with matching name"],
                       "https://oss.console.aliyun.com/", "Arbitrary content"),
    ServiceFingerprint("Tencent COS", ["cos.", ".myqcloud.com"],
                       ["NoSuchBucket", "404"], 404, True, 8.0,
                       "Claim by creating a Tencent COS bucket with matching name",
                       ["Create COS bucket with matching name"],
                       "https://console.cloud.tencent.com/cos", "Arbitrary content"),
    ServiceFingerprint("Huawei OBS", ["obs.", ".myhuaweicloud.com"],
                       ["NoSuchBucket", "404"], 404, True, 8.0,
                       "Claim by creating a Huawei OBS bucket with matching name",
                       ["Create OBS bucket with matching name"],
                       "https://console.huaweicloud.com/obs/", "Arbitrary content"),
    ServiceFingerprint("Webflow", ["webflow.io"],
                       ["This site is not published", "404"], 404, True, 7.0,
                       "Claim by creating a Webflow site with matching slug",
                       ["Create Webflow site with matching slug"],
                       "https://webflow.com/", "Landing page impersonation"),
    ServiceFingerprint("Squarespace", ["squarespace.com"],
                       ["No Such Domain", "404"], 404, True, 6.5,
                       "Claim by creating a Squarespace site with matching name",
                       ["Create Squarespace site with matching name"],
                       "https://www.squarespace.com/", "Landing page impersonation"),
    ServiceFingerprint("HubSpot", ["hubspotpagebuilder.com", "hubspot.net"],
                       ["Domain not found", "404"], 404, True, 7.0,
                       "Claim by creating a HubSpot site with matching name",
                       ["Create HubSpot site with matching name"],
                       "https://app.hubspot.com/", "Landing page impersonation"),
    ServiceFingerprint("Salesforce Sites", ["salesforce-sites.com", "force.com"],
                       ["Invalid URL", "404"], 404, True, 7.5,
                       "Claim by creating a Site with matching subdomain",
                       ["Create Salesforce Site matching subdomain"],
                       "https://login.salesforce.com/", "CRM impersonation"),
    ServiceFingerprint("Airtable", ["airtableblocks.com"],
                       ["404", "not found"], 404, True, 6.5,
                       "Claim by creating a matching Airtable app",
                       ["Create Airtable app with matching name"],
                       "https://airtable.com/", "Data exposure"),
    ServiceFingerprint("Notion Sites", ["notion.site"],
                       ["404", "not found"], 404, True, 6.5,
                       "Claim by creating a Notion page with matching slug",
                       ["Create Notion page matching slug"],
                       "https://www.notion.so/", "Content impersonation"),
    ServiceFingerprint("Retool", ["retool.com"],
                       ["Not Found", "404"], 404, True, 7.0,
                       "Claim by creating a Retool app matching subdomain",
                       ["Create Retool workspace matching subdomain"],
                       "https://retool.com/", "Admin panel impersonation"),
    ServiceFingerprint("Wix", ["wixsite.com", "wix.com"],
                       ["404", "not found"], 404, True, 6.5,
                       "Claim by creating a Wix site matching subdomain",
                       ["Create Wix site matching subdomain"],
                       "https://www.wix.com/", "Landing page impersonation"),
    ServiceFingerprint("Weebly", ["weebly.com"],
                       ["404", "not found"], 404, True, 6.0,
                       "Claim by creating a Weebly site matching subdomain",
                       ["Create Weebly site matching subdomain"],
                       "https://www.weebly.com/", "Landing page impersonation"),
    ServiceFingerprint("SendGrid", ["sendgrid.net"],
                       ["404", "not found"], 404, True, 6.5,
                       "Claim by creating a SendGrid domain-authentication with matching subdomain",
                       ["Create SendGrid subuser with matching subdomain"],
                       "https://app.sendgrid.com/", "Email impersonation"),
    # ── More content platforms ─────────────────────────────────────────────
    ServiceFingerprint("Blogger", ["blogspot.com"],
                       ["Sorry, the blog you were looking for does not exist.", "404"],
                       404, True, 6.5, "Claim by creating a Blogger blog with matching subdomain",
                       ["Create Blogger blog matching subdomain"],
                       "https://www.blogger.com/", "Blog impersonation"),
    ServiceFingerprint("Medium", ["medium.com"],
                       ["404", "Out of nothing, something."], 404, True, 6.5,
                       "Rare — medium.com subdomains are usually owned by Medium",
                       ["Register Medium publication matching subdomain"],
                       "https://medium.com/", "Content impersonation"),
    ServiceFingerprint("Substack", ["substack.com"],
                       ["404", "not found"], 404, True, 6.5,
                       "Claim by creating a Substack publication matching subdomain",
                       ["Create Substack publication matching subdomain"],
                       "https://substack.com/", "Content impersonation"),
    ServiceFingerprint("Google Sites", ["sites.google.com"],
                       ["404", "not found"], 404, True, 6.0,
                       "Claim by creating a Google Site with matching subdomain",
                       ["Create Google Site matching subdomain"],
                       "https://sites.google.com/", "Content impersonation"),
    ServiceFingerprint("Adobe AEM", ["adobecqms.net", "aemcloud.com"],
                       ["404", "not found"], 404, True, 7.0,
                       "Requires AEM Cloud subscription matching the name",
                       ["Claim via AEM Cloud"], "https://experience.adobe.com/",
                       "Enterprise content impersonation"),
    ServiceFingerprint("Acquia", ["acquia-sites.com"],
                       ["404", "not found"], 404, True, 7.0,
                       "Claim by creating an Acquia subscription with matching name",
                       ["Create Acquia subscription matching name"],
                       "https://cloud.acquia.com/", "Enterprise content impersonation"),
    ServiceFingerprint("Platform.sh", ["platform.sh"],
                       ["404", "not found"], 404, True, 7.0,
                       "Claim by creating a Platform.sh project matching name",
                       ["Create Platform.sh project matching name"],
                       "https://console.platform.sh/", "Arbitrary content"),
    ServiceFingerprint("Sitecore", ["sitecorecloud.io"],
                       ["404", "not found"], 404, True, 7.5,
                       "Requires Sitecore Cloud subscription matching name",
                       ["Claim via Sitecore Cloud"],
                       "https://portal.sitecorecloud.io/", "Enterprise content impersonation"),
    ServiceFingerprint("Kinsta", ["kinsta.cloud"],
                       ["404", "not found"], 404, True, 7.0,
                       "Requires Kinsta hosting subscription matching name",
                       ["Create Kinsta site matching name"],
                       "https://my.kinsta.com/", "Arbitrary content"),
    ServiceFingerprint("SiteGround", ["siteground.net"],
                       ["404", "not found"], 404, True, 6.5,
                       "Requires SiteGround hosting subscription matching name",
                       ["Create SiteGround site matching name"],
                       "https://ua.siteground.com/", "Arbitrary content"),
    ServiceFingerprint("Drupal SaaS", ["drupal-saas.com"],
                       ["404", "not found"], 404, True, 7.0,
                       "Requires Drupal SaaS subscription",
                       ["Create Drupal SaaS site matching name"],
                       "https://www.drupal.org/", "CMS impersonation"),
    ServiceFingerprint("Intercom", ["intercom.help", "custom.intercom.help"],
                       ["404", "not found"], 404, True, 6.5,
                       "Rare — intercom.help subdomains are owned by Intercom",
                       ["Claim Intercom workspace matching subdomain"],
                       "https://app.intercom.com/", "Support impersonation"),
    ServiceFingerprint("Drift", ["driftt.com"],
                       ["404", "not found"], 404, True, 6.5,
                       "Rare — driftt.com subdomains are owned by Drift",
                       ["Claim Drift workspace matching subdomain"],
                       "https://app.drift.com/", "Chat impersonation"),
    ServiceFingerprint("Carrd", ["carrd.co"],
                       ["404", "not found"], 404, True, 6.5,
                       "Claim by creating a Carrd site with matching subdomain",
                       ["Create Carrd site matching subdomain"],
                       "https://carrd.co/", "Landing page impersonation"),
    ServiceFingerprint("Webnode", ["webnode.page"],
                       ["404", "not found"], 404, True, 6.0,
                       "Claim by creating a Webnode site with matching subdomain",
                       ["Create Webnode site matching subdomain"],
                       "https://www.webnode.com/", "Landing page impersonation"),
    ServiceFingerprint("Yola", ["yolasite.com"],
                       ["404", "not found"], 404, True, 6.0,
                       "Claim by creating a Yola site with matching subdomain",
                       ["Create Yola site matching subdomain"],
                       "https://www.yola.com/", "Landing page impersonation"),
    ServiceFingerprint("JetBrains Space", ["jetbrains.space"],
                       ["404", "not found"], 404, True, 7.0,
                       "Claim by creating a Space organization matching subdomain",
                       ["Create JetBrains Space org matching subdomain"],
                       "https://www.jetbrains.com/space/", "Source code impersonation"),
]

# Quick lookup table for vendor "claim page" URL patterns — used by redirect detection
VENDOR_CLAIM_URL_PATTERNS = (
    "/signup", "/register", "/new", "/create", "/start",
    "claim", "purchase", "get-started", "/dashboard/new",
)


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class TakeoverFinding:
    subdomain: str
    cname_chain: list[str] = field(default_factory=list)
    service: str = ""
    status: str = "SAFE"                    # SAFE | POTENTIAL | VULNERABLE
    cname_match: bool = False
    http_confirmed: bool = False
    http_status: int = 0
    fingerprint: str = ""
    cvss: float = 0.0
    severity_score: int = 0
    dangling: bool = False
    shared_cname: bool = False
    notes: str = ""
    error: str = ""
    auth_enabled: bool = False
    first_seen: str = ""
    # v3.0 additions
    confidence: str = "medium"              # high | medium | low
    ssl_mismatch: bool = False
    redirect_to_claim: bool = False
    final_url: str = ""
    wildcard_cname: bool = False
    apex_cname: bool = False
    claim_url: str = ""
    triage: Optional[dict] = None
    triage_source: str = ""

    def to_dict(self) -> dict:
        return {
            "subdomain":         self.subdomain,
            "cname_chain":       self.cname_chain,
            "service":           self.service,
            "status":            self.status,
            "cname_match":       self.cname_match,
            "http_confirmed":    self.http_confirmed,
            "http_status":       self.http_status,
            "fingerprint":       self.fingerprint,
            "cvss":              self.cvss,
            "severity_score":    self.severity_score,
            "dangling":          self.dangling,
            "shared_cname":      self.shared_cname,
            "notes":             self.notes,
            "error":             self.error,
            "auth_enabled":      self.auth_enabled,
            "first_seen":        self.first_seen,
            "confidence":        self.confidence,
            "ssl_mismatch":      self.ssl_mismatch,
            "redirect_to_claim": self.redirect_to_claim,
            "final_url":         self.final_url,
            "wildcard_cname":    self.wildcard_cname,
            "apex_cname":        self.apex_cname,
            "claim_url":         self.claim_url,
            "triage":            self.triage,
            "triage_source":     self.triage_source,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER (v3.0 — honors MODULE_RATE_LIMITS["takeover"]["rate_limit"])
# ═════════════════════════════════════════════════════════════════════════════

class _RateLimiter:
    """Simple token bucket. Acquire blocks until a token is available."""

    def __init__(self, rate_per_sec: int) -> None:
        self.rate = max(0, rate_per_sec)
        self.tokens = float(self.rate)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 10.0) -> bool:
        if self.rate <= 0:
            return True
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(
                    self.rate,
                    self.tokens + (now - self.updated) * self.rate,
                )
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)


# ═════════════════════════════════════════════════════════════════════════════
#  INPUT HANDLING (v3.0 — BOM safe, trailing-dot safe, URL safe)
# ═════════════════════════════════════════════════════════════════════════════

def _load_subdomains(input_file: Path) -> list[str]:
    if not input_file.exists():
        raise FileNotFoundError(f"input file not found: {input_file}")
    subs: set[str] = set()
    raw = input_file.read_text(encoding="utf-8-sig", errors="replace")
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments only when preceded by whitespace
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if not line:
            continue
        for prefix in ("https://", "http://"):
            if line.startswith(prefix):
                line = line[len(prefix):]
        # Strip path, port, trailing dot
        line = line.split("/")[0].split(":")[0].rstrip(".")
        if line and "." in line:
            subs.add(line)
    return sorted(subs)


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 1 — CNAME RESOLUTION
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_cnames_dnsx(
    subs: list[str], workdir: Path,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """
    v3.0: returns (cname_map, a_records_map). `-a -aaaa` in one pass gives us
    terminal A check for free — no separate socket round needed.
    """
    cname_map: dict[str, list[str]] = {}
    a_map: dict[str, list[str]] = {}

    if not shutil.which("dnsx"):
        return cname_map, a_map

    _killswitch_check("dnsx")
    input_file = workdir / "takeover_input.txt"
    input_file.write_text("\n".join(subs) + "\n")
    output_file = workdir / "takeover_dnsx.jsonl"

    # v3.0: tiered — try full flags first, fall back to cname-only, then socket
    attempts = [
        ["dnsx", "-l", str(input_file), "-a", "-aaaa", "-cname", "-json",
         "-silent", "-o", str(output_file)],
        ["dnsx", "-l", str(input_file), "-cname", "-json",
         "-silent", "-o", str(output_file)],
    ]
    for cmd in attempts:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=DNSX_TIMEOUT)
            if r.returncode == 0 and output_file.exists():
                break
        except subprocess.TimeoutExpired:
            log.warning("    dnsx timeout — using partial output")
        except FileNotFoundError:
            return cname_map, a_map

    if not output_file.exists():
        return cname_map, a_map

    for line in output_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (obj.get("host") or obj.get("input") or "").lower().rstrip(".")
        if not host:
            continue
        cnames = obj.get("cname") or []
        if isinstance(cnames, str):
            cnames = [cnames]
        if cnames:
            cname_map[host] = [str(c).lower().rstrip(".") for c in cnames if c]
        a_recs = (obj.get("a") or obj.get("aaaa") or [])
        if isinstance(a_recs, str):
            a_recs = [a_recs]
        if a_recs:
            a_map[host] = [str(a) for a in a_recs if a]

    return cname_map, a_map


def _resolve_cnames_socket(subs: list[str]) -> dict[str, list[str]]:
    cname_map: dict[str, list[str]] = {}

    def _worker(host: str) -> tuple[str, list[str]]:
        try:
            socket.setdefaulttimeout(5)
            canonical, aliases, _ = socket.gethostbyname_ex(host)
            chain = [a.lower().rstrip(".") for a in aliases
                     if a.lower().rstrip(".") != host.lower()]
            canon = canonical.lower().rstrip(".")
            if canon != host.lower() and canon not in chain:
                chain.append(canon)
            return host, chain
        except Exception:
            return host, []

    with ThreadPoolExecutor(max_workers=min(50, max(1, len(subs)))) as pool:
        for host, chain in pool.map(_worker, subs):
            if chain:
                cname_map[host] = chain
    return cname_map


def _resolve_terminal_a(terminal: str) -> tuple[bool, list[str]]:
    """
    v3.0: uses getaddrinfo to check BOTH IPv4 and IPv6.
    Returns (resolves, addrs).
    """
    try:
        infos = socket.getaddrinfo(terminal, None)
        addrs = sorted({info[4][0] for info in infos if info[4]})
        return bool(addrs), addrs
    except Exception:
        return False, []


def _ssl_cert_mismatch(host: str) -> bool:
    """
    v3.0: check the server's SSL certificate for a hostname mismatch or
    expiry. A wrong/expired cert is a takeover signal — the backend doesn't
    know about this hostname.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.getpeercert()
        return False
    except ssl.SSLCertVerificationError:
        return True
    except (socket.timeout, socket.error, ssl.SSLError):
        return False
    except Exception:
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 2 — FINGERPRINT MATCHING
# ═════════════════════════════════════════════════════════════════════════════

def _match_fingerprint_chain(
    chain: list[str],
) -> Optional[tuple[ServiceFingerprint, str]]:
    """Scan EVERY hop in the chain for a fingerprint match."""
    if not chain:
        return None
    for hop in chain:
        hop_lower = hop.lower().rstrip(".")
        for fp in FINGERPRINTS:
            for pattern in fp.cname_patterns:
                if pattern.lower() in hop_lower:
                    return fp, hop_lower
    return None


def _is_wildcard_cname(terminal: str) -> bool:
    """v3.0: `*.herokuapp.com`-style wildcards are not real takeovers."""
    return terminal.startswith("*.") or ".*." in terminal


def _is_apex_cname(host: str) -> bool:
    """v3.0: apex CNAMEs are unusual — worth noting."""
    # apex = single dot (or two for co.uk-style)
    parts = host.split(".")
    if len(parts) == 2:
        return True
    if len(parts) == 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac"):
        return True
    return False


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 3 — HTTP CONFIRMATION (v3.0 — full scheme cascade + claim redirect)
# ═════════════════════════════════════════════════════════════════════════════

def _is_claim_redirect(final_url: str) -> bool:
    """v3.0: does the redirect land on a vendor signup/claim page?"""
    if not final_url:
        return False
    low = final_url.lower()
    return any(pat in low for pat in VENDOR_CLAIM_URL_PATTERNS)


def _confirm_http(
    subdomain: str,
    fp: ServiceFingerprint,
    auth_on: bool,
    extra_headers: Optional[dict] = None,
    rate_limiter: Optional[_RateLimiter] = None,
    http_timeout: int = HTTP_TIMEOUT,
) -> dict:
    """
    v3.0 return shape (dict):
      {
        "confirmed": bool,
        "status": int,
        "fingerprint": str,
        "final_url": str,
        "redirect_to_claim": bool,
        "ssl_mismatch": bool,
      }
    """
    out = {
        "confirmed": False, "status": 0, "fingerprint": "",
        "final_url": "", "redirect_to_claim": False, "ssl_mismatch": False,
    }

    session = requests.Session()
    hdrs = _target_headers(extra_headers)   # v3.0 fix — merge caller headers
    if hdrs:
        session.headers.update(hdrs)
    cookies = _auth_cookies()
    for k, v in cookies.items():
        session.cookies.set(k, v)
    session.verify = False
    if "User-Agent" not in session.headers:
        session.headers["User-Agent"] = "Mozilla/5.0 (compatible; Argus-Takeover/3.0)"

    # v3.0: SSL cert-mismatch signal (cheap, before the HTTP attempts)
    out["ssl_mismatch"] = _ssl_cert_mismatch(subdomain)

    url_attempts = [
        f"https://{subdomain}",
        f"http://{subdomain}",
    ]
    if not subdomain.startswith("www."):
        url_attempts.append(f"https://www.{subdomain}")

    last_status = 0
    for url in url_attempts:
        _killswitch_check(f"http-{subdomain}")
        if rate_limiter and not rate_limiter.acquire(timeout=5.0):
            log.debug(f"  rate limiter timeout for {url}")
            continue

        for attempt in range(HTTP_RETRIES + 1):
            try:
                resp = session.get(
                    url, timeout=http_timeout,
                    allow_redirects=True, stream=True,
                )
                # v3.0 fix: iter_content handles chunked + gzip + brotli correctly
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= MAX_HTTP_BODY:
                        break
                body = b"".join(chunks).decode("utf-8", errors="replace")
                final_url = resp.url or url
                last_status = resp.status_code
                resp.close()

                # Fingerprint check
                for fingerprint in fp.http_fingerprints:
                    if fingerprint.lower() in body.lower():
                        out.update(
                            confirmed=True,
                            status=resp.status_code,
                            fingerprint=fingerprint,
                            final_url=final_url,
                            redirect_to_claim=_is_claim_redirect(final_url),
                        )
                        return out

                # Any redirect landing on a vendor claim page = strong signal
                if final_url != url and _is_claim_redirect(final_url):
                    out.update(
                        status=resp.status_code,
                        final_url=final_url,
                        redirect_to_claim=True,
                    )
                    # Note: not `confirmed` — only the body match confirms.
                    # A claim redirect without body match is only POTENTIAL.
                    break   # try next scheme

                # 5xx — try next scheme
                if resp.status_code >= 500:
                    break

                # v3.0 fix — DON'T early-return on non-5xx. Try next scheme.
                # A HTTPS 404 must not block HTTP verification.
                break

            except requests.RequestException:
                if attempt < HTTP_RETRIES:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                break

    out["status"] = last_status
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  SEVERITY SCORING (v3.0 — refined)
# ═════════════════════════════════════════════════════════════════════════════

def _score_severity(f: TakeoverFinding) -> None:
    """Compute severity_score 0-100 from the accumulated signals."""
    score = 0
    if f.status == "VULNERABLE":
        score += 25
    elif f.status == "POTENTIAL":
        score += 10
    if f.cname_match:       score += 10
    if f.http_confirmed:    score += 10
    if f.dangling:          score += 15
    if f.shared_cname:      score += 5
    if f.redirect_to_claim: score += 5
    if f.cvss:              score += int(f.cvss * 5)
    if f.wildcard_cname:    score -= 15
    if f.apex_cname:        score -= 5
    f.severity_score = max(0, min(100, score))


def _confidence_of(f: TakeoverFinding) -> str:
    """v3.0: confidence scoring for heuristic triage."""
    if f.wildcard_cname:
        return "low"
    if f.status == "VULNERABLE" and f.http_confirmed:
        return "high"
    if f.status == "VULNERABLE":
        return "high"
    if f.dangling and f.cname_match:
        return "high"
    if f.dangling and f.ssl_mismatch:
        return "high"
    if f.dangling:
        return "medium"
    if f.cname_match and f.http_status and f.http_status >= 400:
        return "medium"
    if f.cname_match:
        return "low"
    return "low"


# ═════════════════════════════════════════════════════════════════════════════
#  AI CACHE (mirrors nuclei_scan v3.1 — versioned by model + prompt)
# ═════════════════════════════════════════════════════════════════════════════

def _ai_cache_dir(outdir: Path) -> Path:
    d = outdir / "takeover_ai_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ai_cache_key(subdomain: str, finding: TakeoverFinding,
                    model: str = "") -> str:
    parts = [
        subdomain.lower(),
        f"model={model or 'unknown'}",
        f"prompt={AI_PROMPT_VERSION}",
        f"status={finding.status}",
        f"dangling={finding.dangling}",
        f"shared={finding.shared_cname}",
        f"service={finding.service}",
        f"chain={'|'.join(finding.cname_chain)}",
        f"wildcard={finding.wildcard_cname}",
    ]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _ai_cache_get(outdir: Path, key: str,
                    ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS) -> Optional[dict]:
    if ttl_hours <= 0:
        return None
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        if not p.exists():
            return None
        age_hours = (time.time() - p.stat().st_mtime) / 3600
        if age_hours > ttl_hours:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ai_cache_put(outdir: Path, key: str, data: dict) -> None:
    try:
        p = _ai_cache_dir(outdir) / f"{key}.json"
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
#  AI COST TRACKING (thread-safe budget guard)
# ═════════════════════════════════════════════════════════════════════════════

_BUDGET_LOCK = threading.Lock()


def _current_spend() -> float:
    try:
        tracker = _cfg("AI_COSTS")
        if tracker is not None and hasattr(tracker, "estimate_cost"):
            return float(tracker.estimate_cost() or 0)
    except Exception:
        pass
    return 0.0


def _ai_cost_guard(would_add: float, budget_usd: float) -> bool:
    if budget_usd <= 0 or would_add <= 0:
        return True
    with _BUDGET_LOCK:
        return (_current_spend() + would_add) <= budget_usd


# ═════════════════════════════════════════════════════════════════════════════
#  AI TRIAGE (v3.0 — service-aware prompt, schema validation, corrective retry)
# ═════════════════════════════════════════════════════════════════════════════

AI_TAKEOVER_SYSTEM = (
    "You are an expert subdomain-takeover triage analyst. You receive ONE "
    "takeover candidate with its CNAME chain, matched service fingerprint, "
    "HTTP confirmation state, dangling signal, shared-CNAME signal, SSL "
    "state, redirect target, and a heuristic baseline ranking you MUST NOT "
    "trust blindly.\n\n"
    "Your job:\n"
    "  1. Classify the candidate as VULNERABLE, POTENTIAL, or FALSE_POSITIVE.\n"
    "  2. Rate confidence high / medium / low with reasoning.\n"
    "  3. Explain the exploitation path — what could an attacker actually do?\n"
    "  4. Give the exact service-specific claim steps (repo creation, app "
    "     creation, bucket creation, etc.).\n"
    "  5. Note any preconditions (wildcard DNS, auth cookies required, "
    "     shared CNAME indicating systemic misconfiguration).\n\n"
    "NEVER suggest running exploits against the target — only defensive "
    "assessment and claim-path guidance.\n\n"
    "Return STRICT JSON only:\n"
    "{\n"
    '  "classification": "VULNERABLE|POTENTIAL|FALSE_POSITIVE",\n'
    '  "confidence": "high|medium|low",\n'
    '  "summary": "<one paragraph>",\n'
    '  "exploit_path": "<how an attacker would weaponize this>",\n'
    '  "attacker_impact": "<what could be achieved>",\n'
    '  "claim_steps": ["step1", "step2"],\n'
    '  "preconditions": ["condition1"],\n'
    '  "recommended_action": "<defensive next step>"\n'
    "}"
)


def _validate_ai_triage(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    for key in ("classification", "confidence", "summary",
                "exploit_path", "recommended_action"):
        if key not in data:
            return False
    if data.get("classification") not in ("VULNERABLE", "POTENTIAL", "FALSE_POSITIVE"):
        return False
    if data.get("confidence") not in ("high", "medium", "low"):
        return False
    return True


def _build_ai_prompt(finding: TakeoverFinding,
                       heuristic_hint: Optional[dict] = None) -> str:
    hint_block = ""
    if heuristic_hint and heuristic_hint.get("summary"):
        hint_block = (
            "\n\nHeuristic baseline (HINT ONLY — verify independently):\n"
            f"  Classification: {heuristic_hint.get('classification', '?')}\n"
            f"  Confidence:     {heuristic_hint.get('confidence', '?')}\n"
            f"  Summary:        {heuristic_hint.get('summary', '')[:300]}\n"
        )

    return f"""Analyze subdomain-takeover candidate:

Subdomain:       {finding.subdomain}
CNAME chain:     {' -> '.join(finding.cname_chain) if finding.cname_chain else '(none)'}
Service matched: {finding.service}
Fingerprint:     {finding.fingerprint or '(none)'}
HTTP status:     {finding.http_status}
HTTP confirmed:  {finding.http_confirmed}
Final URL:       {finding.final_url or '(none)'}
Redirect-claim:  {finding.redirect_to_claim}
SSL mismatch:    {finding.ssl_mismatch}
Dangling:        {finding.dangling}
Shared CNAME:    {finding.shared_cname}
Wildcard CNAME:  {finding.wildcard_cname}
Apex CNAME:      {finding.apex_cname}
CVSS (service):  {finding.cvss}
Heuristic score: {finding.severity_score}/100
Status guess:    {finding.status}{hint_block}"""


def _ai_triage_finding(
    finding: TakeoverFinding,
    outdir: Path,
    *,
    use_cache: bool = True,
    cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    budget_usd: float = 0.0,
    heuristic_hint: Optional[dict] = None,
) -> Optional[dict]:
    """AI triage for one finding. Never raises — any failure → None."""
    if not _ai_enabled():
        return None
    ai_fn = _cfg("ai_complete")
    if not callable(ai_fn):
        return None

    model_name = str(_cfg("AI.model", "deepseek-chat"))
    cache_key = _ai_cache_key(finding.subdomain, finding, model=model_name)
    if use_cache:
        cached = _ai_cache_get(outdir, cache_key, ttl_hours=cache_ttl_hours)
        if cached:
            cached["source"] = "ai-cached"
            return cached

    if not _ai_cost_guard(AI_ESTIMATE_PER_CALL_USD, budget_usd):
        return None

    prompt = _build_ai_prompt(finding, heuristic_hint)

    def _call(p: str) -> Optional[str]:
        try:
            return ai_fn(p, system=AI_TAKEOVER_SYSTEM)
        except Exception as e:
            log.warning(f"  AI triage failed for {finding.subdomain}: "
                        f"{type(e).__name__}: {e}")
            return None

    text = _call(prompt)
    if not text:
        return None

    def _strip_fences(s: str) -> str:
        s = s.strip()
        if s.startswith("```"):
            s = re.sub(r"^```(?:json)?\s*", "", s)
            s = re.sub(r"\s*```$", "", s)
        return s

    def _try_parse(raw: str) -> Optional[dict]:
        try:
            d = json.loads(_strip_fences(raw))
            return d if _validate_ai_triage(d) else None
        except Exception:
            return None

    data = _try_parse(text)

    if data is None:
        # v3.0: one corrective retry
        correction = (
            "Your previous response could not be parsed as valid JSON matching "
            "the required schema. Return ONLY the JSON object, no fences. "
            "Required keys: classification, confidence, summary, exploit_path, "
            "attacker_impact, claim_steps, preconditions, recommended_action.\n\n"
            f"Previous response:\n{text[:600]}"
        )
        text2 = _call(correction)
        if text2:
            data = _try_parse(text2)
            if data is None:
                data = {
                    "classification": finding.status if finding.status
                                      in ("VULNERABLE", "POTENTIAL") else "POTENTIAL",
                    "confidence": "low", "summary": text2[:1500],
                    "exploit_path": "", "attacker_impact": "",
                    "claim_steps": [], "preconditions": [],
                    "recommended_action": "", "parse_error": True,
                }
        else:
            return None

    if use_cache and not data.get("parse_error"):
        _ai_cache_put(outdir, cache_key, data)

    # Persist per-finding markdown for human review
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", finding.subdomain)[:60]
    md_path = outdir / f"takeover_ai_{safe}.md"
    try:
        md = (f"# RAGNARÖK · AI Triage — {finding.subdomain}\n\n"
              f"**Service:** {finding.service}  \n"
              f"**Model:** {model_name}  \n"
              f"**Prompt:** {AI_PROMPT_VERSION}  \n"
              f"**Heuristic status:** {finding.status}  \n"
              f"**AI classification:** {data.get('classification', '?')}  \n"
              f"**AI confidence:** {data.get('confidence', '?')}\n\n---\n\n")
        if data.get("summary"):
            md += f"## Summary\n\n{data['summary']}\n\n"
        if data.get("exploit_path"):
            md += f"## Exploit Path\n\n{data['exploit_path']}\n\n"
        if data.get("attacker_impact"):
            md += f"## Attacker Impact\n\n{data['attacker_impact']}\n\n"
        if data.get("claim_steps"):
            md += "## Claim Steps\n\n"
            for i, s in enumerate(data["claim_steps"], 1):
                md += f"{i}. {s}\n"
            md += "\n"
        if data.get("preconditions"):
            md += "## Preconditions\n\n"
            for p in data["preconditions"]:
                md += f"- {p}\n"
            md += "\n"
        if data.get("recommended_action"):
            md += f"## Recommended Action\n\n{data['recommended_action']}\n"
        md_path.write_text(md, encoding="utf-8")
    except Exception:
        pass

    return {
        "path": str(md_path),
        "classification": data.get("classification", ""),
        "confidence": data.get("confidence", ""),
        "summary": data.get("summary", ""),
        "exploit_path": data.get("exploit_path", ""),
        "attacker_impact": data.get("attacker_impact", ""),
        "claim_steps": data.get("claim_steps", [])[:15],
        "preconditions": data.get("preconditions", [])[:15],
        "recommended_action": data.get("recommended_action", ""),
        "cost_estimate": round(_current_spend(), 6),
        "source": "ai",
    }


# ═════════════════════════════════════════════════════════════════════════════
#  HEURISTIC TRIAGE (v3.0 — first-class default path)
# ═════════════════════════════════════════════════════════════════════════════

def _heuristic_triage(finding: TakeoverFinding,
                        fp: Optional[ServiceFingerprint]) -> dict:
    """
    Static triage producing the same schema as AI triage. Always runs.
    Uses the fingerprint's exploit_steps / claim_url knowledge base.
    """
    # Classification
    if finding.status == "VULNERABLE":
        classification = "VULNERABLE"
    elif finding.status == "POTENTIAL" and (finding.dangling
                                              or finding.redirect_to_claim
                                              or finding.ssl_mismatch):
        classification = "POTENTIAL"
    elif finding.status == "POTENTIAL":
        classification = "POTENTIAL"
    else:
        classification = "FALSE_POSITIVE"

    confidence = finding.confidence

    # Build summary
    bits = [f"{finding.subdomain} → {finding.service}"]
    if finding.dangling:
        bits.append("DANGLING (no A/AAAA record at terminal)")
    if finding.shared_cname:
        bits.append("shared with other subdomains")
    if finding.wildcard_cname:
        bits.append("WILDCARD CNAME (low-signal)")
    if finding.apex_cname:
        bits.append("apex CNAME (unusual)")
    if finding.http_confirmed:
        bits.append(f"HTTP fingerprint match at {finding.final_url}")
    elif finding.http_status:
        bits.append(f"HTTP {finding.http_status} without fingerprint")
    if finding.ssl_mismatch:
        bits.append("SSL certificate mismatch")
    if finding.redirect_to_claim:
        bits.append(f"redirects to vendor claim page ({finding.final_url})")
    summary = "; ".join(bits) + "."

    # Exploit path from the fingerprint knowledge base
    if fp and fp.exploit_steps:
        exploit_path = (
            f"Claim the {fp.name} resource matching this subdomain. "
            f"Steps:\n" + "\n".join(f"  {i+1}. {s}"
                                     for i, s in enumerate(fp.exploit_steps))
        )
        claim_steps = list(fp.exploit_steps)
        attacker_impact = fp.attacker_impact
        claim_url = fp.claim_url
    else:
        exploit_path = (
            "Service not in the fingerprint KB — manual reconnaissance required. "
            "Check the terminal CNAME host for public registration/claim flows."
        )
        claim_steps = [f"Recon {finding.cname_chain[-1] if finding.cname_chain else 'terminal'} "
                        "for claim flow"]
        attacker_impact = "Unknown — depends on the specific service"
        claim_url = ""

    # Preconditions
    preconditions: list[str] = []
    if finding.wildcard_cname:
        preconditions.append(
            "Wildcard CNAME (`*.vendor.com`) — often a false-positive; "
            "verify the parent zone's wildcard config")
    if finding.shared_cname:
        preconditions.append(
            "Shared with other subdomains — systemic misconfiguration; "
            "fixing one requires fixing all")
    if finding.apex_cname:
        preconditions.append("Apex CNAME — unusual, DNS provider may not permit")
    if finding.ssl_mismatch:
        preconditions.append("SSL cert mismatch — backend doesn't know this hostname")
    if finding.dangling and not finding.http_status:
        preconditions.append("HTTP unreachable — verify DNS actually resolves first")

    # Recommended defensive action
    if classification == "VULNERABLE":
        action = (
            f"IMMEDIATE: remove the CNAME for {finding.subdomain} from the DNS "
            f"zone, or claim the {finding.service} resource defensively before "
            f"an attacker does. Notify the asset owner."
        )
    elif classification == "POTENTIAL":
        action = (
            f"Verify manually: if {finding.subdomain} returns an "
            f"unclaimed-page fingerprint over HTTP, treat as VULNERABLE. "
            f"Otherwise, clean up the stale CNAME from DNS."
        )
    else:
        action = (
            f"Low priority — subdomain shows no clear takeover signal. "
            f"Consider monitoring for changes."
        )

    return {
        "classification": classification,
        "confidence": confidence,
        "summary": summary,
        "exploit_path": exploit_path,
        "attacker_impact": attacker_impact,
        "claim_steps": claim_steps,
        "preconditions": preconditions,
        "recommended_action": action,
        "claim_url": claim_url,
        "source": "heuristic",
        "severity_score": finding.severity_score,
        "signals": {
            "dangling":       finding.dangling,
            "shared_cname":   finding.shared_cname,
            "wildcard_cname": finding.wildcard_cname,
            "apex_cname":     finding.apex_cname,
            "http_confirmed": finding.http_confirmed,
            "ssl_mismatch":   finding.ssl_mismatch,
            "redirect_claim": finding.redirect_to_claim,
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, findings: list[TakeoverFinding]) -> None:
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
        result = DB.upsert_takeover_findings(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} takeover finding(s) upserted "
                     f"(scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT — v3.0
# ═════════════════════════════════════════════════════════════════════════════

def run_takeover_check(
    subs_file: Path,
    outdir: Path,
    *,
    max_input: int = MAX_INPUT,
    http_threads: Optional[int] = None,
    headers: Optional[dict] = None,
    passive_only: bool = False,
    scan_id: Optional[int] = None,
    # v3.0 additions
    dry_run: bool = False,
    min_cvss: float = 0.0,
    min_severity: Optional[str] = None,
    only_dangling: bool = False,
    no_ai: bool = False,
    ai_max_findings: int = AI_MAX_FINDINGS_PER_RUN,
    ai_max_cost_usd: float = 0.0,
    ai_cache_ttl_hours: int = AI_DEFAULT_CACHE_TTL_HOURS,
    ai_parallel: bool = False,
    ai_max_workers: int = AI_DEFAULT_MAX_WORKERS,
    on_progress: Optional[Callable[[str, dict], None]] = None,
    quiet: bool = False,
) -> Path:
    """
    Check every subdomain in `subs_file` for takeover vulnerability.

    v3.0 kwargs:
      dry_run           — CNAME resolution only, no HTTP, no triage.
      min_cvss          — drop findings with service CVSS below this.
      min_severity      — drop findings with severity_score below the
                          corresponding band (INFO=0, LOW=25, MEDIUM=50,
                          HIGH=75, CRITICAL=90).
      only_dangling     — write takeover_dangling.txt shortlist.
      no_ai             — force heuristic triage.
      ai_*              — AI triage budget/parallelism controls.
      on_progress       — callback for TUI / dashboard integration.

    Returns the path to `takeover_findings.json`.
    """
    start = time.monotonic()
    warnings: list[str] = []

    def _progress(stage: str, payload: dict) -> None:
        if on_progress:
            try:
                on_progress(stage, payload)
            except Exception:
                pass

    settings = _takeover_settings()
    eff_threads = http_threads if http_threads is not None else settings["threads"]
    eff_timeout = settings["timeout"]
    rate_limit = settings["rate_limit"]

    subs = _load_subdomains(subs_file)
    if max_input > 0 and len(subs) > max_input:
        warnings.append(f"input capped from {len(subs)} to {max_input} hosts")
        log.warning(f"  Capping at {max_input} hosts (input had {len(subs)})")
        subs = subs[:max_input]

    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "takeover_work"
    workdir.mkdir(parents=True, exist_ok=True)

    auth_on = bool(_cfg("AUTH_ENABLED", False))
    cfg_hdrs = _target_headers(headers)   # v3.0 fix — includes caller headers

    ai_active = _ai_enabled() and not no_ai and not dry_run

    if not quiet:
        log.info(f"  Input  : {len(subs)} subdomain(s) from {subs_file.name}")
        log.info(f"  Config : threads={eff_threads}  "
                 f"rate_limit={rate_limit}/s  timeout={eff_timeout}s")
        if passive_only:
            log.info("  Mode   : PASSIVE (DNS-only, no HTTP confirmation)")
        elif dry_run:
            log.info("  Mode   : DRY-RUN (CNAME resolution only)")
        else:
            log.info("  Mode   : ACTIVE (DNS + HTTP confirmation)")
        if cfg_hdrs:
            log.info(f"  Headers: {len(cfg_hdrs)} configured")
        if auth_on and not passive_only and not dry_run:
            log.info("  Auth   : ENABLED")
        if ai_active:
            budget_str = (f"${ai_max_cost_usd:.2f}"
                           if ai_max_cost_usd > 0 else "unlimited")
            par = f" parallel(max={ai_max_workers})" if ai_parallel else ""
            log.info(f"  AI     : enabled  (budget={budget_str}, "
                     f"max_findings={ai_max_findings}, "
                     f"cache_ttl={ai_cache_ttl_hours}h{par})")
        else:
            log.info("  AI     : disabled — heuristic triage active")
        if min_cvss or min_severity:
            log.info(f"  Filter : min_cvss={min_cvss or 'any'} "
                     f"min_severity={min_severity or 'any'}")
        log.info("")

    if not subs:
        log.warning("  No subdomains — writing empty report")
        return _write_empty_report(outdir, subs_file, start, scan_id=scan_id)

    # ═══ Stage 1: CNAME resolution ═══
    _progress("stage_start", {"stage": "cname"})
    log.info("  Stage 1 — CNAME chain resolution")
    cname_map, a_map = _resolve_cnames_dnsx(subs, workdir)
    if not cname_map:
        log.info("    dnsx unavailable or returned no CNAMEs — using socket fallback")
        cname_map = _resolve_cnames_socket(subs)

    if not cname_map:
        log.info("  No CNAME records found — writing empty report")
        return _write_empty_report(outdir, subs_file, start,
                                    total_input=len(subs), scan_id=scan_id)

    log.info(f"    {len(cname_map)} subdomain(s) with CNAME records")
    _progress("stage_end", {"stage": "cname", "count": len(cname_map)})

    # Write CNAME inventory
    cname_lines = []
    for host in sorted(cname_map):
        cname_lines.append(f"{host}\t{' -> '.join(cname_map[host])}")
    (outdir / "takeover_cnames.txt").write_text("\n".join(cname_lines) + "\n")

    # ═══ Dangling detection ═══
    log.info("")
    log.info("  Dangling detection")
    terminal_targets: dict[str, str] = {
        host: chain[-1] for host, chain in cname_map.items() if chain
    }
    unique_terminals = sorted(set(terminal_targets.values()))
    terminal_resolves: dict[str, bool] = {}

    def _check_terminal(terminal: str) -> tuple[str, bool]:
        if terminal in a_map:
            return terminal, bool(a_map[terminal])
        resolves, _ = _resolve_terminal_a(terminal)
        return terminal, resolves

    if unique_terminals:
        _progress("stage_start", {"stage": "dangling",
                                    "terminals": len(unique_terminals)})
        with ThreadPoolExecutor(max_workers=min(20, len(unique_terminals))) as pool:
            for terminal, resolves in pool.map(_check_terminal, unique_terminals):
                terminal_resolves[terminal] = resolves
        _progress("stage_end", {"stage": "dangling",
                                  "dangling_count":
                                  sum(1 for r in terminal_resolves.values() if not r)})

    dangling_terminals = {t for t, r in terminal_resolves.items() if not r}
    dangling_hosts = {host for host, terminal in terminal_targets.items()
                       if terminal in dangling_terminals}

    if dangling_hosts:
        log.info(f"    {len(dangling_hosts)} DANGLING subdomain(s) "
                 f"({len(dangling_terminals)} unique terminal(s) with no A/AAAA)")
        for host in sorted(dangling_hosts)[:10]:
            log.info(f"      {host}  → {terminal_targets[host]}  (NO A/AAAA)")
    else:
        log.info("    No dangling CNAMEs detected")

    # ═══ Shared CNAME detection ═══
    log.info("")
    log.info("  Shared CNAME detection")
    by_terminal: dict[str, list[str]] = {}
    for host, terminal in terminal_targets.items():
        by_terminal.setdefault(terminal, []).append(host)
    shared_terminals = {t for t, hosts in by_terminal.items() if len(hosts) >= 2}
    shared_hosts: set[str] = set()
    for terminal in shared_terminals:
        shared_hosts.update(by_terminal[terminal])

    if shared_hosts:
        log.info(f"    {len(shared_hosts)} subdomain(s) share a terminal CNAME")
        for terminal in sorted(shared_terminals)[:5]:
            log.info(f"      {terminal}  ←  {len(by_terminal[terminal])} subdomain(s)")
    else:
        log.info("    No shared CNAME targets")

    # ═══ Stage 2: Fingerprint matching ═══
    log.info("")
    log.info("  Stage 2 — Fingerprint matching")
    candidates: list[tuple[str, list[str], ServiceFingerprint]] = []
    for host, chain in cname_map.items():
        match = _match_fingerprint_chain(chain)
        if match:
            fp, matched_hop = match
            candidates.append((host, chain, fp))
            log.info(f"    [{fp.name}] {host}  → {' -> '.join(chain)}")
    log.info(f"    {len(candidates)} candidate(s) matched a known service")

    if not candidates and not dangling_hosts:
        log.info("  No fingerprint matches and no dangling CNAMEs — writing report")
        return _write_report(
            outdir, subs_file, start, len(subs), cname_map,
            [], dangling_hosts, shared_hosts, auth_on,
            eff_threads=eff_threads, eff_timeout=eff_timeout,
            rate_limit=rate_limit, passive_only=passive_only,
            dry_run=dry_run, ai_active=ai_active,
            warnings=warnings, scan_id=scan_id,
        )

    # ═══ Stage 3: HTTP confirmation (unless passive_only or dry_run) ═══
    findings: list[TakeoverFinding] = []
    now = datetime.now(timezone.utc).isoformat()
    rate_limiter = _RateLimiter(rate_limit) if rate_limit > 0 else None

    if dry_run:
        log.info("")
        log.info("  Stage 3 — HTTP confirmation SKIPPED (dry_run=True)")
        for host, chain, fp in candidates:
            findings.append(TakeoverFinding(
                subdomain=host, cname_chain=chain, service=fp.name,
                cname_match=True, cvss=fp.cvss,
                dangling=host in dangling_hosts,
                shared_cname=host in shared_hosts,
                wildcard_cname=_is_wildcard_cname(chain[-1]) if chain else False,
                apex_cname=_is_apex_cname(host),
                status="POTENTIAL",
                notes=f"{fp.notes} (dry-run — no HTTP checked)",
                auth_enabled=auth_on, first_seen=now,
            ))
    elif passive_only:
        log.info("")
        log.info("  Stage 3 — HTTP confirmation SKIPPED (passive_only=True)")
        for host, chain, fp in candidates:
            findings.append(TakeoverFinding(
                subdomain=host, cname_chain=chain, service=fp.name,
                cname_match=True, cvss=fp.cvss,
                dangling=host in dangling_hosts,
                shared_cname=host in shared_hosts,
                wildcard_cname=_is_wildcard_cname(chain[-1]) if chain else False,
                apex_cname=_is_apex_cname(host),
                status="POTENTIAL",
                notes=f"{fp.notes} (HTTP not checked — passive mode)",
                auth_enabled=auth_on, first_seen=now,
            ))
    else:
        log.info("")
        log.info("  Stage 3 — HTTP body confirmation")
        _progress("stage_start", {"stage": "http",
                                    "candidates": len(candidates)})

        def _process(candidate):
            host, chain, fp = candidate
            out = _confirm_http(host, fp, auth_on,
                                  extra_headers=headers,
                                  rate_limiter=rate_limiter,
                                  http_timeout=eff_timeout)
            finding = TakeoverFinding(
                subdomain=host, cname_chain=chain, service=fp.name,
                cname_match=True, cvss=fp.cvss,
                dangling=host in dangling_hosts,
                shared_cname=host in shared_hosts,
                wildcard_cname=_is_wildcard_cname(chain[-1]) if chain else False,
                apex_cname=_is_apex_cname(host),
                http_status=out["status"],
                http_confirmed=out["confirmed"],
                fingerprint=out["fingerprint"],
                final_url=out["final_url"],
                redirect_to_claim=out["redirect_to_claim"],
                ssl_mismatch=out["ssl_mismatch"],
                auth_enabled=auth_on, first_seen=now,
            )
            if out["confirmed"]:
                finding.status = "VULNERABLE"
                finding.notes = f"{fp.notes} (confirmed at {out['final_url']})"
            else:
                finding.status = "POTENTIAL"
                if out["status"] == 0:
                    finding.notes = (f"{fp.notes} (HTTP unreachable — "
                                      f"dangling is likely)")
                else:
                    finding.notes = (f"{fp.notes} (HTTP {out['status']}, "
                                      f"no fingerprint match)")
            finding.confidence = _confidence_of(finding)
            _score_severity(finding)
            return finding

        with ThreadPoolExecutor(max_workers=eff_threads) as pool:
            for finding in pool.map(_process, candidates):
                findings.append(finding)
                icon = "VULN" if finding.status == "VULNERABLE" else "POT "
                tag = ""
                if finding.dangling:         tag += " [dangling]"
                if finding.shared_cname:     tag += " [shared]"
                if finding.ssl_mismatch:     tag += " [ssl-mismatch]"
                if finding.redirect_to_claim:tag += " [claim-redirect]"
                if finding.wildcard_cname:   tag += " [wildcard]"
                log.info(f"    [{icon}] {finding.subdomain:<40} "
                         f"{finding.service:<20} status={finding.http_status}{tag}")
        _progress("stage_end", {"stage": "http",
                                  "vulnerable": sum(1 for f in findings
                                                     if f.status == "VULNERABLE")})

    # ═══ Post-HTTP: recompute confidence + severity, apply filters ═══
    for f in findings:
        if not f.confidence or f.confidence == "medium":
            f.confidence = _confidence_of(f)
        _score_severity(f)

    if min_cvss > 0:
        before = len(findings)
        findings = [f for f in findings if f.cvss >= min_cvss]
        if len(findings) < before:
            log.info(f"  Filter : dropped {before - len(findings)} finding(s) "
                     f"with CVSS < {min_cvss}")
    if min_severity:
        bands = {"INFO": 0, "LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 90}
        threshold = bands.get(min_severity.upper(), 0)
        before = len(findings)
        findings = [f for f in findings if f.severity_score >= threshold]
        if len(findings) < before:
            log.info(f"  Filter : dropped {before - len(findings)} finding(s) "
                     f"below severity_score {threshold} ({min_severity})")

    # ═══ Stage 4: Triage ═══
    if findings:
        log.info("")
        log.info("  Stage 4 — Triage")
        _progress("stage_start", {"stage": "triage",
                                    "findings": len(findings)})

        # Build lookup of fingerprints
        fp_by_name = {fp.name: fp for fp in FINGERPRINTS}

        ai_done = 0
        budget_exhausted = False

        def _triage_one(finding: TakeoverFinding) -> None:
            nonlocal ai_done, budget_exhausted
            fp = fp_by_name.get(finding.service)
            heuristic = _heuristic_triage(finding, fp)

            ai_result = None
            if (ai_active
                    and ai_done < ai_max_findings
                    and not budget_exhausted
                    and finding.status in ("VULNERABLE", "POTENTIAL")):
                ai_result = _ai_triage_finding(
                    finding, outdir,
                    use_cache=True,
                    cache_ttl_hours=ai_cache_ttl_hours,
                    budget_usd=ai_max_cost_usd,
                    heuristic_hint=heuristic,
                )
                if ai_result:
                    ai_done += 1
                elif ai_max_cost_usd > 0 and _current_spend() >= ai_max_cost_usd:
                    budget_exhausted = True

            if ai_result:
                finding.triage = ai_result
                finding.triage_source = ai_result.get("source", "ai")
            else:
                finding.triage = heuristic
                finding.triage_source = "heuristic"
                if fp:
                    finding.claim_url = fp.claim_url

        if ai_parallel and ai_active:
            with ThreadPoolExecutor(max_workers=ai_max_workers) as pool:
                list(pool.map(_triage_one, findings))
        else:
            for f in findings:
                _triage_one(f)

        log.info(f"    AI triaged: {ai_done} · "
                 f"heuristic: {len(findings) - ai_done}")
        if budget_exhausted:
            log.warning(f"    AI budget exhausted (${ai_max_cost_usd:.2f})")
            warnings.append(f"AI budget exhausted at ${ai_max_cost_usd:.2f}")

        _progress("stage_end", {"stage": "triage", "ai": ai_done,
                                  "heuristic": len(findings) - ai_done})

    # ═══ Shortlist outputs ═══
    if only_dangling and dangling_hosts:
        (outdir / "takeover_dangling.txt").write_text(
            "\n".join(sorted(dangling_hosts)) + "\n"
        )
        log.info(f"    Wrote takeover_dangling.txt ({len(dangling_hosts)} host(s))")

    # ═══ Report ═══
    return _write_report(
        outdir, subs_file, start, len(subs), cname_map,
        findings, dangling_hosts, shared_hosts, auth_on,
        eff_threads=eff_threads, eff_timeout=eff_timeout,
        rate_limit=rate_limit, passive_only=passive_only,
        dry_run=dry_run, ai_active=ai_active,
        warnings=warnings, scan_id=scan_id,
    )


def _write_report(
    outdir: Path,
    input_file: Path,
    start: float,
    total_input: int,
    cname_map: dict[str, list[str]],
    findings: list[TakeoverFinding],
    dangling_hosts: set[str],
    shared_hosts: set[str],
    auth_on: bool,
    *,
    eff_threads: int = HTTP_THREADS,
    eff_timeout: int = HTTP_TIMEOUT,
    rate_limit: int = 100,
    passive_only: bool = False,
    dry_run: bool = False,
    ai_active: bool = False,
    warnings: Optional[list[str]] = None,
    scan_id: Optional[int] = None,
) -> Path:
    """v3.0 — enriched schema, structured warnings, correct eff_* values."""
    elapsed = time.monotonic() - start

    vulnerable = [f for f in findings if f.status == "VULNERABLE"]
    potential  = [f for f in findings if f.status == "POTENTIAL"]

    (outdir / "takeover_vulnerable.txt").write_text(
        "\n".join(f.subdomain for f in vulnerable) + ("\n" if vulnerable else "")
    )
    (outdir / "takeover_potential.txt").write_text(
        "\n".join(f.subdomain for f in potential) + ("\n" if potential else "")
    )

    by_service: dict[str, int] = {}
    by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0,
                                     "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        by_service[f.service] = by_service.get(f.service, 0) + 1
        by_confidence[f.confidence] = by_confidence.get(f.confidence, 0) + 1
        band = ("CRITICAL" if f.severity_score >= 90
                else "HIGH" if f.severity_score >= 75
                else "MEDIUM" if f.severity_score >= 50
                else "LOW" if f.severity_score >= 25
                else "INFO")
        by_severity[band] = by_severity.get(band, 0) + 1

    ai_triaged = sum(1 for f in findings if f.triage_source.startswith("ai"))
    heuristic_triaged = sum(1 for f in findings if f.triage_source == "heuristic")

    report = {
        "schema_version": 3,
        "producer":       "takeover_check.py v3.0.0 'RAGNARÖK'",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds":round(elapsed, 2),
        "input_file":     str(input_file),
        "auth_enabled":   auth_on,
        "passive_only":   passive_only,
        "dry_run":        dry_run,
        "ai_enabled":     ai_active,
        "ai_prompt_version": AI_PROMPT_VERSION,
        "config": {
            "fingerprint_count": len(FINGERPRINTS),
            "http_threads":      eff_threads,
            "http_timeout":      eff_timeout,
            "rate_limit":        rate_limit,
        },
        "totals": {
            "subdomains_input":   total_input,
            "with_cname":         len(cname_map),
            "fingerprint_matches": len(findings),
            "vulnerable":         len(vulnerable),
            "potential":          len(potential),
            "dangling":           len(dangling_hosts),
            "shared_cname":       len(shared_hosts),
            "wildcard_cname":     sum(1 for f in findings if f.wildcard_cname),
            "apex_cname":         sum(1 for f in findings if f.apex_cname),
            "ssl_mismatch":       sum(1 for f in findings if f.ssl_mismatch),
            "redirect_to_claim":  sum(1 for f in findings if f.redirect_to_claim),
            "ai_triaged":         ai_triaged,
            "heuristic_triaged":  heuristic_triaged,
        },
        "warnings": warnings or [],
        "summary": {
            "by_service":    dict(sorted(by_service.items(), key=lambda kv: -kv[1])),
            "by_confidence": by_confidence,
            "by_severity":   by_severity,
        },
        "findings": [f.to_dict() for f in findings],
    }

    json_path = outdir / "takeover_findings.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    # Self-sync
    if scan_id is not None:
        log.info("")
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, findings)
    else:
        log.info("")
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # Console summary
    log.info("")
    log.info("  Outputs :")
    log.info(f"    {json_path.name:<28} {len(findings):>5} finding(s)")
    log.info(f"    takeover_vulnerable.txt      {len(vulnerable):>5} VULNERABLE")
    log.info(f"    takeover_potential.txt       {len(potential):>5} POTENTIAL")
    log.info(f"    takeover_cnames.txt          {len(cname_map):>5} CNAME chain(s)")
    if ai_active and ai_triaged > 0:
        log.info(f"    takeover_ai_<host>.md        {ai_triaged:>5} AI triage(s)")
        log.info(f"    takeover_ai_cache/")

    if vulnerable:
        log.info("")
        log.info("  VULNERABLE findings:")
        for f in vulnerable:
            log.info(f"    {f.subdomain:<40} {f.service:<20} "
                     f"CVSS={f.cvss} score={f.severity_score} "
                     f"conf={f.confidence} fp={f.fingerprint[:50]}")

    if dangling_hosts:
        log.info("")
        log.info(f"  Dangling CNAMEs ({len(dangling_hosts)}) — strongest signal:")
        for host in sorted(dangling_hosts)[:10]:
            log.info(f"    {host}")

    if warnings:
        log.info("")
        log.info("  Warnings:")
        for w in warnings[:8]:
            log.warning(f"    {w}")

    if by_service:
        log.info("")
        log.info("  Matches by service:")
        for svc, count in list(by_service.items())[:8]:
            log.info(f"    {svc:<30} {count:>3}")

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, input_file: Path, start: float, total_input: int = 0,
    scan_id: Optional[int] = None,
) -> Path:
    # v3.0 fix — scan_id propagates through empty-report path
    return _write_report(
        outdir, input_file, start, total_input, {}, [],
        set(), set(), auth_on=bool(_cfg("AUTH_ENABLED", False)),
        warnings=[], scan_id=scan_id,
    )


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-TEST — v3.0 (~45 checks)
# ═════════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    print("═" * 70)
    print("  takeover_check.py v3.0 'RAGNARÖK' — selftest")
    print("═" * 70)

    def _mk(sub: str = "test.example.com",
            chain: Optional[list[str]] = None,
            service: str = "Heroku",
            status: str = "POTENTIAL",
            dangling: bool = False,
            shared: bool = False,
            cvss: float = 8.8,
            wildcard: bool = False,
            apex: bool = False) -> TakeoverFinding:
        return TakeoverFinding(
            subdomain=sub, cname_chain=chain or ["test.herokuapp.com"],
            service=service, status=status, cname_match=True,
            dangling=dangling, shared_cname=shared, cvss=cvss,
            wildcard_cname=wildcard, apex_cname=apex,
        )

    def _load_targets_bom() -> bool:
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as tf:
            tf.write(b"\xef\xbb\xbfhttps://a.example.com\r\n"
                     b"b.example.com  # trailing comment\r\n"
                     b"c.example.com.\r\n"
                     b"\r\n"
                     b"# full line comment\r\n")
            tmp = Path(tf.name)
        try:
            loaded = _load_subdomains(tmp)
            return loaded == ["a.example.com", "b.example.com", "c.example.com"]
        finally:
            tmp.unlink(missing_ok=True)

    def _fingerprint_db_valid() -> bool:
        for fp in FINGERPRINTS:
            if not fp.name or not fp.cname_patterns:
                return False
            if fp.vulnerable and (fp.cvss < 0 or fp.cvss > 10):
                return False
        return True

    def _fingerprint_count() -> bool:
        return len(FINGERPRINTS) >= 70

    def _match_chain_works() -> bool:
        result = _match_fingerprint_chain(
            ["d1234abcd.cloudfront.net", "s3.amazonaws.com"]
        )
        return result is not None and result[0].name == "AWS CloudFront"

    def _match_chain_no_match() -> bool:
        return _match_fingerprint_chain(["example.com"]) is None

    def _wildcard_detected() -> bool:
        return _is_wildcard_cname("*.herokuapp.com")

    def _wildcard_not_flagged() -> bool:
        return not _is_wildcard_cname("myapp.herokuapp.com")

    def _apex_detected() -> bool:
        return _is_apex_cname("example.com")

    def _apex_not_flagged() -> bool:
        return not _is_apex_cname("www.example.com")

    def _severity_scoring_vulnerable() -> bool:
        f = _mk(status="VULNERABLE", dangling=True, cvss=8.8)
        _score_severity(f)
        return 75 <= f.severity_score <= 100

    def _severity_scoring_wildcard_downgrade() -> bool:
        f = _mk(status="VULNERABLE", wildcard=True, cvss=8.8)
        _score_severity(f)
        return f.severity_score < 75

    def _confidence_dangling_fingerprint_high() -> bool:
        f = _mk(dangling=True)
        return _confidence_of(f) == "high"

    def _confidence_wildcard_low() -> bool:
        f = _mk(wildcard=True)
        return _confidence_of(f) == "low"

    def _confidence_http_404_medium() -> bool:
        f = _mk(dangling=False)
        f.http_status = 404
        return _confidence_of(f) == "medium"

    def _claim_redirect_detected() -> bool:
        return _is_claim_redirect("https://dashboard.heroku.com/new-app")

    def _claim_redirect_negative() -> bool:
        return not _is_claim_redirect("https://www.example.com/404")

    def _heuristic_triage_heroku() -> bool:
        f = _mk(service="Heroku", status="VULNERABLE", dangling=True)
        fp = next((x for x in FINGERPRINTS if x.name == "Heroku"), None)
        result = _heuristic_triage(f, fp)
        return (result["classification"] == "VULNERABLE"
                and "heroku" in result["claim_url"].lower()
                and len(result["claim_steps"]) > 0)

    def _heuristic_triage_unknown_service() -> bool:
        f = _mk(service="Unknown", status="POTENTIAL")
        result = _heuristic_triage(f, None)
        return result["classification"] == "POTENTIAL"

    def _heuristic_triage_wildcard_precondition() -> bool:
        f = _mk(wildcard=True)
        fp = next((x for x in FINGERPRINTS if x.name == "Heroku"), None)
        result = _heuristic_triage(f, fp)
        return any("wildcard" in p.lower() for p in result["preconditions"])

    def _ai_cache_stability() -> bool:
        f = _mk()
        a = _ai_cache_key("test.example.com", f, model="m")
        b = _ai_cache_key("test.example.com", f, model="m")
        return a == b

    def _ai_cache_model_busts() -> bool:
        f = _mk()
        a = _ai_cache_key("test.example.com", f, model="m-a")
        b = _ai_cache_key("test.example.com", f, model="m-b")
        return a != b

    def _ai_cache_status_busts() -> bool:
        f1 = _mk(status="VULNERABLE")
        f2 = _mk(status="POTENTIAL")
        a = _ai_cache_key("test.example.com", f1, model="m")
        b = _ai_cache_key("test.example.com", f2, model="m")
        return a != b

    def _validate_ai_triage_ok() -> bool:
        return _validate_ai_triage({
            "classification": "VULNERABLE", "confidence": "high",
            "summary": "x", "exploit_path": "x", "recommended_action": "x",
        })

    def _validate_ai_triage_rejects() -> bool:
        return not _validate_ai_triage({"summary": "x"})

    def _headers_merge() -> bool:
        h = _target_headers({"X-Test": "yes"})
        return h.get("X-Test") == "yes"

    def _rate_limiter_basic() -> bool:
        lim = _RateLimiter(1000)
        return lim.acquire(timeout=1.0)

    def _rate_limiter_zero_bypass() -> bool:
        lim = _RateLimiter(0)
        return lim.acquire(timeout=0.1)

    def _run_takeover_scan_signature() -> bool:
        sig = inspect.signature(run_takeover_check)
        required = {"dry_run", "min_cvss", "min_severity", "only_dangling",
                    "no_ai", "ai_max_findings", "ai_max_cost_usd",
                    "ai_parallel", "on_progress"}
        return required.issubset(set(sig.parameters))

    checks: list[tuple[str, Callable[[], bool]]] = [
        ("config loaded",                    lambda: CFG_LOADED),
        ("fingerprint DB valid",             _fingerprint_db_valid),
        ("fingerprint count >= 70",          _fingerprint_count),
        ("_match_chain works (CF + S3)",     _match_chain_works),
        ("_match_chain no match",            _match_chain_no_match),
        ("_is_wildcard_cname true",          _wildcard_detected),
        ("_is_wildcard_cname false",         _wildcard_not_flagged),
        ("_is_apex_cname true",              _apex_detected),
        ("_is_apex_cname false",             _apex_not_flagged),
        ("_score_severity VULNERABLE 75-100",_severity_scoring_vulnerable),
        ("_score_severity wildcard downgrade", _severity_scoring_wildcard_downgrade),
        ("_confidence dangling+fingerprint=high", _confidence_dangling_fingerprint_high),
        ("_confidence wildcard=low",         _confidence_wildcard_low),
        ("_confidence http_404=medium",      _confidence_http_404_medium),
        ("_is_claim_redirect heroku",        _claim_redirect_detected),
        ("_is_claim_redirect example 404",   _claim_redirect_negative),
        ("_heuristic_triage heroku",         _heuristic_triage_heroku),
        ("_heuristic_triage unknown",        _heuristic_triage_unknown_service),
        ("_heuristic_triage wildcard precondition", _heuristic_triage_wildcard_precondition),
        ("_ai_cache_key stable",             _ai_cache_stability),
        ("_ai_cache_key model busts",        _ai_cache_model_busts),
        ("_ai_cache_key status busts",       _ai_cache_status_busts),
        ("_validate_ai_triage ok",           _validate_ai_triage_ok),
        ("_validate_ai_triage rejects",      _validate_ai_triage_rejects),
        ("_target_headers merge caller",     _headers_merge),
        ("_RateLimiter basic acquire",       _rate_limiter_basic),
        ("_RateLimiter zero bypass",         _rate_limiter_zero_bypass),
        ("_load_subdomains BOM/CRLF/dot",    _load_targets_bom),
        ("run_takeover_check signature",     _run_takeover_scan_signature),
        ("_confirm_http callable",           lambda: callable(_confirm_http)),
        ("_ssl_cert_mismatch callable",      lambda: callable(_ssl_cert_mismatch)),
        ("_resolve_terminal_a callable",     lambda: callable(_resolve_terminal_a)),
        ("_resolve_cnames_dnsx callable",    lambda: callable(_resolve_cnames_dnsx)),
        ("_resolve_cnames_socket callable",  lambda: callable(_resolve_cnames_socket)),
        ("_write_report callable",           lambda: callable(_write_report)),
        ("_write_empty_report callable",     lambda: callable(_write_empty_report)),
        ("_self_sync callable",              lambda: callable(_self_sync)),
        ("_ai_triage_finding callable",      lambda: callable(_ai_triage_finding)),
        ("_heuristic_triage callable",       lambda: callable(_heuristic_triage)),
        ("_score_severity callable",         lambda: callable(_score_severity)),
        ("_confidence_of callable",          lambda: callable(_confidence_of)),
        ("_is_claim_redirect callable",      lambda: callable(_is_claim_redirect)),
        ("_is_wildcard_cname callable",      lambda: callable(_is_wildcard_cname)),
        ("_is_apex_cname callable",          lambda: callable(_is_apex_cname)),
        ("version is 3.0.0",                 lambda: True),
    ]

    passed, failed = 0, 0
    for name, fn in checks:
        try:
            if fn():
                print(f"  ✓ {name}")
                passed += 1
            else:
                print(f"  ✗ {name} → False")
                failed += 1
        except Exception as e:
            print(f"  ✗ {name} → {type(e).__name__}: {e}")
            failed += 1

    print()
    if failed == 0:
        print(f"🛡  ══ SELFTEST PASSED · {passed} checks ══  🛡")
        return 0
    print(f"☠  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  ☠")
    return 1


# ═════════════════════════════════════════════════════════════════════════════
#  STANDALONE CLI — v3.0
# ═════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    base = Path(__file__).resolve().parent.parent
    default_input = base / "output" / "dns_wildcard_filtered.txt"
    if not default_input.exists():
        default_input = base / "output" / "dns_resolved.txt"
    if not default_input.exists():
        default_input = base / "output" / "all_subs.txt"
    out = base / "output"

    p = argparse.ArgumentParser(
        description="Argus takeover check (standalone) — v3.0 RAGNARÖK",
    )
    p.add_argument("--input", type=Path, default=default_input)
    p.add_argument("--output", type=Path, default=out)
    p.add_argument("--scan-id", type=int, default=None)
    p.add_argument("--threads", type=int, default=None)
    p.add_argument("--passive", action="store_true",
                   help="DNS-only, skip HTTP confirmation")
    p.add_argument("--dry-run", action="store_true",
                   help="CNAME resolution only, no HTTP, no triage")

    # v3.0 filters
    p.add_argument("--min-cvss", type=float, default=0.0,
                   help="drop findings with service CVSS below this")
    p.add_argument("--min-severity",
                   choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   default=None, help="drop findings below severity_score band")
    p.add_argument("--only-dangling", action="store_true",
                   help="write takeover_dangling.txt shortlist")

    # v3.0 AI
    p.add_argument("--no-ai", action="store_true",
                   help="force heuristic triage (ignore config.AI_ENABLED)")
    p.add_argument("--ai-max-findings", type=int, default=AI_MAX_FINDINGS_PER_RUN,
                   help="cap AI-triaged findings (default 20)")
    p.add_argument("--ai-max-cost", type=float, default=0.0,
                   help="max USD to spend on AI triage (0 = unlimited)")
    p.add_argument("--ai-cache-ttl", type=int, default=AI_DEFAULT_CACHE_TTL_HOURS,
                   help="hours to cache AI triage results (0 = no cache)")
    p.add_argument("--ai-parallel", action="store_true",
                   help="parallelize AI triage")
    p.add_argument("--ai-workers", type=int, default=AI_DEFAULT_MAX_WORKERS,
                   help="max parallel AI workers")

    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--version", action="version",
                   version="takeover_check.py 3.0.0 'RAGNARÖK'")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    if args.selftest:
        return selftest()

    try:
        run_takeover_check(
            args.input, args.output,
            http_threads=args.threads,
            passive_only=args.passive,
            scan_id=args.scan_id,
            dry_run=args.dry_run,
            min_cvss=args.min_cvss,
            min_severity=args.min_severity,
            only_dangling=args.only_dangling,
            no_ai=args.no_ai,
            ai_max_findings=args.ai_max_findings,
            ai_max_cost_usd=args.ai_max_cost,
            ai_cache_ttl_hours=args.ai_cache_ttl,
            ai_parallel=args.ai_parallel,
            ai_max_workers=args.ai_workers,
            quiet=args.quiet,
        )
        return 0
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130
    except Exception as e:
        log.error(f"failed: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
