#!/usr/bin/env python3
"""
auditing_tools/site_crawler.py — Authenticated Site Crawler
═══════════════════════════════════════════════════════════════════════════════

Renders every reachable page on every live host, extracts links/forms,
classifies auth surfaces, takes screenshots, and stores everything in the
`site_pages` database table.

Playwright is optional:
  • If installed  → Chromium render, full-page screenshots, JS-aware
  • If not        → requests + BeautifulSoup fallback, no screenshots

AUTHENTICATION
──────────────
If `request.txt` exists and parses cleanly, its cookies and headers are
injected into every request. This lets the crawler see the authenticated
surface that only registered users can reach.

`request.txt` is populated MANUALLY:
  1. You register / log in to the target in your browser
  2. Capture any authenticated request from Burp Suite
  3. Save it to `request.txt` in the Argus root

The crawler NEVER submits forms. It NEVER registers accounts. It NEVER
reads email. It ONLY replays the session you already authenticated.
See ACCEPTABLE_USE.md.

Outputs (into `outdir`):
  • site_pages.json       — full structured report
  • site_pages.txt        — flat URL + kind list
  • auth_pages.txt        — every login/register page (for manual work)
  • screenshots/          — one PNG per page (Playwright mode only)

Remote DB (when scan_id is provided):
  • site_pages table      — one row per (scan_id, url_hash)

Integration:
  main.py → run_one("crawl") → run_site_crawl(live_urls_file, outdir)
  Also self-syncs when scan_id is passed (standalone mode)
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("argus.site_crawler")

# ═════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═════════════════════════════════════════════════════════════════════════════

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


def _cfg(key: str, default=None):
    if not CFG_LOADED:
        return default
    return getattr(CFG, key, default)


# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_MAX_PAGES_PER_HOST = 100
DEFAULT_MAX_DEPTH          = 2
DEFAULT_PAGE_TIMEOUT_MS    = 15000
DEFAULT_PAGE_DELAY         = 1.0
DEFAULT_CONCURRENCY        = 2

SCREENSHOT_DIR_NAME = "screenshots"

# Auth-related URL patterns
LOGIN_PATH_PATTERNS    = re.compile(
    r"/(login|signin|sign-in|log-in|authenticate|auth|session|sso|signon)",
    re.I,
)
REGISTER_PATH_PATTERNS = re.compile(
    r"/(register|signup|sign-up|create[-_]?account|join|onboard)",
    re.I,
)
ADMIN_PATH_PATTERNS    = re.compile(
    r"/(admin|dashboard|console|management|internal|cp|panel)",
    re.I,
)
API_PATH_PATTERNS      = re.compile(
    r"/(api|graphql|rest|v\d+|gql)(/|$)",
    re.I,
)


# ═════════════════════════════════════════════════════════════════════════════
#  PLAYWRIGHT DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def _has_playwright() -> bool:
    """True if playwright is importable and chromium is installed."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


# ═════════════════════════════════════════════════════════════════════════════
#  DATA MODEL
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CrawlConfig:
    max_pages: int = DEFAULT_MAX_PAGES_PER_HOST
    max_depth: int = DEFAULT_MAX_DEPTH
    timeout_ms: int = DEFAULT_PAGE_TIMEOUT_MS
    page_delay: float = DEFAULT_PAGE_DELAY
    auth_enabled: bool = False
    auth_headers: dict[str, str] = field(default_factory=dict)
    auth_cookies: list[dict] = field(default_factory=list)
    auth_host: str = ""
    outdir: Path = field(default_factory=Path)


@dataclass
class PageRecord:
    url: str
    host: str
    path: str
    title: str = ""
    content_type: str = ""
    status_code: int = 0
    page_kind: str = "other"
    is_auth_page: bool = False
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    screenshot_path: str = ""
    response_time: str = ""
    rendered_html_length: int = 0
    auth_enabled: bool = False
    first_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "url":                  self.url,
            "host":                 self.host,
            "path":                 self.path,
            "title":                self.title,
            "content_type":         self.content_type,
            "status_code":          self.status_code,
            "page_kind":            self.page_kind,
            "is_auth_page":         self.is_auth_page,
            "forms":                self.forms,
            "links":                self.links[:200],
            "screenshot_path":      self.screenshot_path,
            "response_time":        self.response_time,
            "rendered_html_length": self.rendered_html_length,
            "auth_enabled":         self.auth_enabled,
            "first_seen":           self.first_seen,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

def _load_hosts(input_file: Path) -> list[str]:
    """Load hosts from a URL list or host list."""
    if not input_file.exists():
        return []
    hosts: list[str] = []
    seen: set[str] = set()
    for line in input_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if not token.startswith(("http://", "https://")):
            token = "https://" + token
        parsed = urllib.parse.urlparse(token)
        if not parsed.hostname:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            hosts.append(base)
    return hosts


def _normalize_url(url: str, base_host: str) -> Optional[str]:
    """
    Normalize a URL for comparison. Returns None if:
      • Not HTTP/HTTPS
      • Different host from base_host (external link)
      • Static asset (images, fonts, etc.)
    """
    if not url:
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if parsed.hostname != base_host:
        return None

    # Strip fragment
    normalized = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc.lower(),
        parsed.path or "/",
        "",
        parsed.query,
        "",
    ))

    # Skip static assets
    path_lower = parsed.path.lower()
    for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".otf",
                ".css", ".map", ".mp4", ".webm", ".mp3",
                ".pdf", ".zip", ".tar", ".gz"):
        if path_lower.endswith(ext):
            return None

    return normalized


def _classify_page(url: str, title: str, forms: list) -> tuple[str, bool]:
    """
    Classify a page. Returns (page_kind, is_auth_page).
    """
    path = urllib.parse.urlparse(url).path or "/"
    title_lower = (title or "").lower()

    # Path-based classification
    if REGISTER_PATH_PATTERNS.search(path):
        return "register", True
    if LOGIN_PATH_PATTERNS.search(path):
        return "login", True
    if ADMIN_PATH_PATTERNS.search(path):
        return "admin", True
    if API_PATH_PATTERNS.search(path):
        return "api", False

    # Form-based classification (more reliable than path)
    has_password_field = False
    has_confirm_password = False
    has_username_or_email = False

    for form in forms or []:
        for field in form.get("fields", []):
            ftype = (field.get("type") or "").lower()
            fname = (field.get("name") or "").lower()

            if ftype == "password":
                has_password_field = True
                # Heuristic: password confirm fields usually have "confirm" or "repeat"
                if "confirm" in fname or "repeat" in fname or "verify" in fname:
                    has_confirm_password = True
            if ftype in ("email",) or "email" in fname or "username" in fname:
                has_username_or_email = True

    if has_password_field and has_confirm_password:
        return "register", True
    if has_password_field and has_username_or_email:
        return "login", True

    # Title-based heuristics
    if "sign up" in title_lower or "register" in title_lower or "create account" in title_lower:
        return "register", True
    if "sign in" in title_lower or "login" in title_lower or "log in" in title_lower:
        return "login", True

    return "public", False


# ═════════════════════════════════════════════════════════════════════════════
#  PLAYWRIGHT CRAWLER
# ═════════════════════════════════════════════════════════════════════════════

def _crawl_with_playwright(
    base_url: str, cfg: CrawlConfig,
) -> list[PageRecord]:
    """Full-fidelity crawl with Chromium rendering + screenshots."""
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    base_host = urllib.parse.urlparse(base_url).hostname or ""
    screenshots_dir = cfg.outdir / SCREENSHOT_DIR_NAME / base_host
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    pages: list[PageRecord] = []
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url + "/", 0)]

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        )
        context = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=cfg.auth_headers if cfg.auth_enabled else None,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        # Inject cookies — only for the auth host and its subdomains
        if cfg.auth_enabled and cfg.auth_cookies and cfg.auth_host:
            if base_host == cfg.auth_host or base_host.endswith("." + cfg.auth_host):
                domain_cookies = []
                for c in cfg.auth_cookies:
                    domain_cookies.append({
                        "name":  c["name"],
                        "value": c["value"],
                        "domain": "." + cfg.auth_host,
                        "path":  "/",
                    })
                try:
                    context.add_cookies(domain_cookies)
                    log.info(f"    {base_host}: injected {len(domain_cookies)} auth cookie(s)")
                except Exception as e:
                    log.warning(f"    cookie injection failed: {e}")

        page = context.new_page()

        while queue and len(pages) < cfg.max_pages:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            if depth > cfg.max_depth:
                continue
            visited.add(url)

            try:
                t0 = time.monotonic()
                response = page.goto(
                    url, timeout=cfg.timeout_ms, wait_until="domcontentloaded",
                )
                elapsed = time.monotonic() - t0

                status = response.status if response else 0
                title = page.title() or ""
                ct = (response.headers.get("content-type", "") if response else "")
                html_len = len(page.content() or "")

                # Extract links
                raw_links = page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.href).filter(Boolean)",
                ) or []

                # Extract forms (metadata only — never filled)
                forms = page.eval_on_selector_all(
                    "form",
                    """els => els.map(f => ({
                        action: f.action || '',
                        method: (f.method || 'get').toLowerCase(),
                        fields: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                            name: i.name || '',
                            type: (i.type || 'text').toLowerCase(),
                            required: i.required === true,
                        })),
                    }))""",
                ) or []

                # Screenshot
                slug = re.sub(r"[^a-zA-Z0-9]+", "_", url)[:80].strip("_") or "root"
                shot_path = screenshots_dir / f"{slug}.png"
                try:
                    page.screenshot(path=str(shot_path), full_page=True)
                    shot_rel = str(shot_path.relative_to(cfg.outdir))
                except Exception as e:
                    log.debug(f"screenshot failed on {url}: {e}")
                    shot_rel = ""

                # Normalize links
                normalized = []
                for link in raw_links:
                    n = _normalize_url(link, base_host)
                    if n and n not in visited:
                        normalized.append(n)
                        queue.append((n, depth + 1))

                kind, is_auth = _classify_page(url, title, forms)

                pages.append(PageRecord(
                    url=url,
                    host=base_host,
                    path=urllib.parse.urlparse(url).path or "/",
                    title=title,
                    content_type=ct,
                    status_code=status,
                    page_kind=kind,
                    is_auth_page=is_auth,
                    forms=forms,
                    links=list(dict.fromkeys(normalized))[:200],
                    screenshot_path=shot_rel,
                    response_time=f"{elapsed*1000:.0f}ms",
                    rendered_html_length=html_len,
                    auth_enabled=cfg.auth_enabled,
                    first_seen=datetime.now(timezone.utc).isoformat(),
                ))

                log.info(
                    f"    [{kind:<8}] {status:>3}  {url[:60]:<60}  "
                    f"({len(normalized)} links, {len(forms)} forms)"
                )

                time.sleep(cfg.page_delay)

            except PWTimeout:
                log.warning(f"    timeout: {url}")
            except Exception as e:
                log.warning(f"    failed: {url}: {str(e)[:80]}")

        browser.close()

    return pages


# ═════════════════════════════════════════════════════════════════════════════
#  REQUESTS FALLBACK CRAWLER
# ═════════════════════════════════════════════════════════════════════════════

def _crawl_with_requests(
    base_url: str, cfg: CrawlConfig,
) -> list[PageRecord]:
    """
    Fallback crawler using requests + BeautifulSoup (if available) or regex.

    No screenshots. No JS rendering. Works for static sites.
    """
    try:
        import requests
    except ImportError:
        log.warning("    neither playwright nor requests available — skipping")
        return []

    base_host = urllib.parse.urlparse(base_url).hostname or ""

    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Argus-Crawler/1.0"})

    if cfg.auth_enabled and cfg.auth_headers:
        session.headers.update(cfg.auth_headers)
    if cfg.auth_enabled and cfg.auth_cookies and cfg.auth_host:
        if base_host == cfg.auth_host or base_host.endswith("." + cfg.auth_host):
            for c in cfg.auth_cookies:
                session.cookies.set(c["name"], c["value"], domain=cfg.auth_host)

    pages: list[PageRecord] = []
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url + "/", 0)]

    # Try beautifulsoup
    try:
        from bs4 import BeautifulSoup
        has_bs4 = True
    except ImportError:
        has_bs4 = False

    while queue and len(pages) < cfg.max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        if depth > cfg.max_depth:
            continue
        visited.add(url)

        try:
            t0 = time.monotonic()
            r = session.get(
                url,
                timeout=cfg.timeout_ms / 1000.0,
                allow_redirects=True,
                verify=False,
            )
            elapsed = time.monotonic() - t0

            title = ""
            raw_links: list[str] = []
            forms: list = []

            if has_bs4:
                soup = BeautifulSoup(r.text, "html.parser")
                title = (soup.title.string or "").strip() if soup.title else ""
                raw_links = [a.get("href") for a in soup.find_all("a", href=True)]
                for f in soup.find_all("form"):
                    fields = []
                    for i in f.find_all(["input", "select", "textarea"]):
                        fields.append({
                            "name": i.get("name") or "",
                            "type": (i.get("type") or "text").lower(),
                            "required": i.has_attr("required"),
                        })
                    forms.append({
                        "action": f.get("action") or "",
                        "method": (f.get("method") or "get").lower(),
                        "fields": fields,
                    })
            else:
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
                if m:
                    title = m.group(1).strip()
                raw_links = re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', r.text, re.I)

            # Normalize links
            normalized = []
            for link in raw_links:
                if not link:
                    continue
                absolute = urllib.parse.urljoin(url, link)
                n = _normalize_url(absolute, base_host)
                if n and n not in visited:
                    normalized.append(n)
                    queue.append((n, depth + 1))

            kind, is_auth = _classify_page(url, title, forms)

            pages.append(PageRecord(
                url=url,
                host=base_host,
                path=urllib.parse.urlparse(url).path or "/",
                title=title,
                content_type=r.headers.get("Content-Type", ""),
                status_code=r.status_code,
                page_kind=kind,
                is_auth_page=is_auth,
                forms=forms,
                links=list(dict.fromkeys(normalized))[:200],
                screenshot_path="",
                response_time=f"{elapsed*1000:.0f}ms",
                rendered_html_length=len(r.text),
                auth_enabled=cfg.auth_enabled,
                first_seen=datetime.now(timezone.utc).isoformat(),
            ))

            log.info(
                f"    [{kind:<8}] {r.status_code:>3}  {url[:60]:<60}  "
                f"({len(normalized)} links, {len(forms)} forms)"
            )

            time.sleep(cfg.page_delay)

        except Exception as e:
            log.warning(f"    failed: {url}: {str(e)[:80]}")

    return pages


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS
# ═════════════════════════════════════════════════════════════════════════════

def _write_txt(pages: list[PageRecord], outdir: Path) -> Path:
    lines = [
        f"{p.page_kind}\t{p.status_code}\t{p.url}"
        for p in pages
    ]
    path = outdir / "site_pages.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _write_auth_pages(pages: list[PageRecord], outdir: Path) -> Path:
    auth_pages = [p for p in pages if p.is_auth_page]
    lines = [
        f"{p.page_kind}\t{p.url}"
        for p in auth_pages
    ]
    path = outdir / "auth_pages.txt"
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def _print_auth_warning(pages: list[PageRecord], auth_enabled: bool) -> None:
    """If auth pages found and auth not enabled, print manual registration hint."""
    if auth_enabled:
        return

    auth_pages = [p for p in pages if p.is_auth_page]
    if not auth_pages:
        return

    log.info("")
    log.info("  " + "─" * 69)
    log.info(f"  ⚠  Found {len(auth_pages)} authentication page(s):")
    for p in auth_pages[:10]:
        log.info(f"       [{p.page_kind:<8}] {p.url}")
    log.info("")
    log.info("     To crawl the authenticated surface:")
    log.info("       1. Register / log in manually in your browser")
    log.info("       2. Open Burp Suite, capture any authenticated request")
    log.info("       3. Paste the raw request into request.txt")
    log.info("       4. Re-run this stage")
    log.info("  " + "─" * 69)
    log.info("")


# ═════════════════════════════════════════════════════════════════════════════
#  SELF-SYNC
# ═════════════════════════════════════════════════════════════════════════════

def _self_sync(scan_id: int, pages: list[PageRecord]) -> None:
    if not pages:
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
    if not DB.available:
        log.warning("  DB sync: bridge client not ready")
        return

    try:
        payloads = [p.to_dict() for p in pages]
        result = DB.upsert_site_pages(scan_id, payloads)
        if result is None:
            log.warning("  DB sync: bridge returned None")
        else:
            log.info(f"  DB sync: {result} page(s) upserted (scan_id={scan_id})")
    except Exception as e:
        log.warning(f"  DB sync: exception — {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  PUBLIC ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def run_site_crawl(
    live_urls_file: Path,
    outdir: Path,
    *,
    max_pages: int = DEFAULT_MAX_PAGES_PER_HOST,
    max_depth: int = DEFAULT_MAX_DEPTH,
    page_delay: float = DEFAULT_PAGE_DELAY,
    force_requests: bool = False,
    scan_id: Optional[int] = None,
) -> Path:
    """
    Crawl every live host and record every page.

    Uses Playwright if available (screenshots + JS), else falls back to
    requests + BeautifulSoup.

    Returns the path to `site_pages.json`.
    """
    start = time.monotonic()

    if not live_urls_file.exists():
        raise FileNotFoundError(f"input not found: {live_urls_file}")

    hosts = _load_hosts(live_urls_file)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"  Input  : {len(hosts)} host(s) from {live_urls_file.name}")

    if not hosts:
        log.warning("  No hosts to crawl — writing empty report")
        return _write_empty_report(outdir, live_urls_file, start)

    # ── Auth status ─────────────────────────────────────────────────────────
    auth_enabled = bool(_cfg("AUTH_ENABLED", False))
    auth_host = _cfg("AUTH_HOST", "") or ""
    auth_headers = _cfg("AUTH_HEADERS", {}) or {}
    auth_cookies_dict = _cfg("AUTH_COOKIES", {}) or {}

    if auth_enabled:
        log.info(f"  Auth   : ENABLED ({auth_host}, "
                 f"{len(auth_headers)} headers, {len(auth_cookies_dict)} cookies)")
        log.info(f"           request.txt: loaded")
    else:
        log.info(f"  Auth   : disabled (no request.txt or parse failed)")
        log.info(f"           To enable: register manually → save request from Burp")

    # Convert cookies to Playwright format
    auth_cookies_pw: list[dict] = [
        {"name": k, "value": v}
        for k, v in auth_cookies_dict.items()
    ]

    # ── Crawl mode ──────────────────────────────────────────────────────────
    use_playwright = not force_requests and _has_playwright()

    if use_playwright:
        log.info(f"  Engine : Playwright/Chromium (renders JS, takes screenshots)")
    else:
        if force_requests:
            log.info(f"  Engine : requests+BS4 (forced via --requests)")
        else:
            log.info(f"  Engine : requests+BS4 (Playwright not installed)")
            log.info(f"           To enable Playwright: pip install playwright")
            log.info(f"                                 playwright install chromium")
    log.info(f"  Limits : max_pages={max_pages}  max_depth={max_depth}  "
             f"delay={page_delay}s")
    log.info("")

    # ── Build config ────────────────────────────────────────────────────────
    cfg = CrawlConfig(
        max_pages=max_pages,
        max_depth=max_depth,
        timeout_ms=DEFAULT_PAGE_TIMEOUT_MS,
        page_delay=page_delay,
        auth_enabled=auth_enabled,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies_pw,
        auth_host=auth_host,
        outdir=outdir,
    )

    # ── Crawl each host ─────────────────────────────────────────────────────
    all_pages: list[PageRecord] = []
    by_host: dict[str, list[PageRecord]] = {}

    for i, base_url in enumerate(hosts, 1):
        host = urllib.parse.urlparse(base_url).hostname or base_url
        log.info(f"  [{i}/{len(hosts)}] {host}")

        try:
            if use_playwright:
                pages = _crawl_with_playwright(base_url, cfg)
            else:
                pages = _crawl_with_requests(base_url, cfg)
        except Exception as e:
            log.warning(f"    crawl failed: {str(e)[:100]}")
            pages = []

        all_pages.extend(pages)
        by_host[host] = pages
        log.info("")

    # ── Deduplicate by URL ──────────────────────────────────────────────────
    seen_urls: set[str] = set()
    deduped: list[PageRecord] = []
    for p in all_pages:
        if p.url not in seen_urls:
            seen_urls.add(p.url)
            deduped.append(p)

    deduped.sort(key=lambda p: (p.page_kind, p.host, p.path))

    # ── Summary ─────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - start
    by_kind: dict[str, int] = {}
    for p in deduped:
        by_kind[p.page_kind] = by_kind.get(p.page_kind, 0) + 1

    auth_pages = [p for p in deduped if p.is_auth_page]

    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "input_file":      str(live_urls_file),
        "auth_enabled":    auth_enabled,
        "auth_host":       auth_host,
        "engine":          "playwright" if use_playwright else "requests",
        "config": {
            "max_pages":  max_pages,
            "max_depth":  max_depth,
            "page_delay": page_delay,
        },
        "totals": {
            "hosts":         len(hosts),
            "pages_crawled": len(deduped),
            "auth_pages":    len(auth_pages),
            "register_pages": by_kind.get("register", 0),
            "login_pages":   by_kind.get("login", 0),
            "admin_pages":   by_kind.get("admin", 0),
            "api_pages":     by_kind.get("api", 0),
        },
        "by_kind":    by_kind,
        "auth_pages": [p.to_dict() for p in auth_pages],
        "pages":      [p.to_dict() for p in deduped],
    }

    # ── Write outputs ───────────────────────────────────────────────────────
    json_path = outdir / "site_pages.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    txt_path = _write_txt(deduped, outdir)
    auth_path = _write_auth_pages(deduped, outdir)

    # ── Auth hint (if not enabled) ──────────────────────────────────────────
    _print_auth_warning(deduped, auth_enabled)

    # ── Self-sync (standalone) ──────────────────────────────────────────────
    if scan_id is not None:
        log.info(f"  Syncing to remote database (scan_id={scan_id})...")
        _self_sync(scan_id, deduped)
    else:
        log.info("  DB sync  : deferred to main.py (no scan_id passed)")

    # ── Console summary ─────────────────────────────────────────────────────
    log.info("")
    log.info(f"  Outputs :")
    log.info(f"    {json_path.name:<22} {len(deduped):>5} page(s)")
    log.info(f"    {txt_path.name:<22} {len(deduped):>5} line(s)")
    log.info(f"    {auth_path.name:<22} {len(auth_pages):>5} auth page(s)")
    if use_playwright:
        log.info(f"    {SCREENSHOT_DIR_NAME + '/':<22} {len(deduped):>5} screenshot(s)")

    log.info("")
    log.info(f"  By kind : " + " · ".join(
        f"{k}({v})" for k, v in sorted(by_kind.items(), key=lambda kv: -kv[1])
    ))

    log.info("")
    log.info(f"  Completed in {elapsed:.1f}s")
    return json_path


def _write_empty_report(
    outdir: Path, input_file: Path, start: float,
) -> Path:
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "input_file":      str(input_file),
        "auth_enabled":    bool(_cfg("AUTH_ENABLED", False)),
        "engine":          "none",
        "totals":          {"hosts": 0, "pages_crawled": 0, "auth_pages": 0},
        "by_kind":         {},
        "auth_pages":      [],
        "pages":           [],
    }
    path = outdir / "site_pages.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "site_pages.txt").write_text("")
    (outdir / "auth_pages.txt").write_text("")
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
    default_input = base / "output" / "live_urls.txt"
    out = base / "output"

    parser = argparse.ArgumentParser(description="Argus site crawler (standalone)")
    parser.add_argument("--input", type=Path, default=default_input)
    parser.add_argument("--output", type=Path, default=out)
    parser.add_argument("--scan-id", type=int, default=None)
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES_PER_HOST)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--delay", type=float, default=DEFAULT_PAGE_DELAY)
    parser.add_argument("--requests", action="store_true",
                        help="force requests+BS4 mode, skip Playwright")
    args = parser.parse_args()

    try:
        run_site_crawl(
            args.input, args.output,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            page_delay=args.delay,
            force_requests=args.requests,
            scan_id=args.scan_id,
        )
    except Exception as e:
        log.error(f"failed: {e}")
        sys.exit(1)
