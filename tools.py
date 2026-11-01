#!/usr/bin/env python3
"""
tools.py — Argus dependency installer & verifier
================================================

Detects, installs, and verifies every tool Argus needs on Debian-based
systems (Debian, Ubuntu, Kali, Parrot, Pop!_OS, Linux Mint).

Design goals:
  • Idempotent — safe to rerun. Only installs what's missing.
  • Deterministic — every tool has a registry entry with a known method.
  • Verifiable — every install is confirmed by a post-install probe.
  • Debian-safe — respects PEP 668; uses apt for Python libs.
  • Non-destructive — a dry-run shows what would happen without changing state.

Usage:
    python3 tools.py                    # interactive install (prompts for sudo)
    python3 tools.py --check            # verify only, exit non-zero if missing
    python3 tools.py --dry-run          # show what would be done
    python3 tools.py --yes              # non-interactive (assume yes)
    python3 tools.py --category recon   # install only a category
    python3 tools.py --only nuclei,httpx
    python3 tools.py --skip sqlmap,nikto
    python3 tools.py --no-color --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

IS_ROOT = os.geteuid() == 0
HOME = Path.home()
GO_BIN_DIR = HOME / "go" / "bin"
GO_INSTALL_DIR = Path("/usr/local/go")
SECLISTS_PATHS = [Path("/usr/share/seclists"), Path("/opt/seclists")]
LOG_DIR = Path(__file__).parent / "output"

# Colors — applied only when stdout is a TTY
C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[90m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "magenta": "\033[35m",
}


# ─────────────────────────────────────────────────────────────────────────────
# Tool Registry
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Tool:
    """One installable dependency."""
    name: str
    category: str                     # base | recon | scan | audit | util | resource
    method: str                       # apt | go | git | special
    package: str                      # apt pkg, go module path, or git URL
    binary: Optional[str] = None      # binary name if different from `name`
    sudo: bool = False                # requires sudo for install
    check_cmd: Optional[str] = None   # shell command to verify installation
    post_install: list[str] = field(default_factory=list)
    description: str = ""

    @property
    def resolved_binary(self) -> str:
        return self.binary or self.name


# ── Base system packages (installed via apt) ─────────────────────────────────
BASE_PACKAGES = [
    Tool("git",            "base", "apt", "git",            sudo=True,  description="Version control"),
    Tool("curl",           "base", "apt", "curl",           sudo=True,  description="HTTP client"),
    Tool("wget",           "base", "apt", "wget",           sudo=True,  description="HTTP downloader"),
    Tool("unzip",          "base", "apt", "unzip",          sudo=True,  description="Archive extractor"),
    Tool("jq",             "base", "apt", "jq",             sudo=True,  description="JSON processor"),
    Tool("make",           "base", "apt", "make",           sudo=True,  description="Build tool"),
    Tool("gcc",            "base", "apt", "build-essential", binary="gcc", sudo=True, description="C compiler"),
    Tool("dnsutils",       "base", "apt", "dnsutils",       sudo=True,  check_cmd="dig -v", description="DNS utilities (dig)"),
    Tool("whois",          "base", "apt", "whois",          sudo=True,  description="WHOIS lookups"),
    Tool("net-tools",      "base", "apt", "net-tools",      sudo=True,  check_cmd="netstat -V", description="Network utilities (netstat)"),
    Tool("python3-requests","base","apt", "python3-requests", sudo=True, check_cmd="python3 -c 'import requests'", description="Python HTTP library"),
    Tool("python3-venv",   "base", "apt", "python3-venv",   sudo=True,  description="Python venv support"),
]

# ── Scanning / auditing tools (installed via apt where packaged) ─────────────
APT_SECURITY_TOOLS = [
    Tool("nmap",     "scan",  "apt", "nmap",     sudo=True, description="Port & service scanner"),
    Tool("sqlmap",   "audit", "apt", "sqlmap",   sudo=True, check_cmd="sqlmap --version", description="SQL injection scanner"),
    Tool("nikto",    "scan",  "apt", "nikto",    sudo=True, description="Web server scanner"),
    Tool("gobuster", "recon", "apt", "gobuster", sudo=True, check_cmd="gobuster version", description="Dir/DNS/vhost busting"),
]

# ── Go-based tools (installed via `go install`) ──────────────────────────────
GO_TOOLS = [
    # ProjectDiscovery
    Tool("subfinder",   "recon", "go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",  check_cmd="subfinder -version", description="Passive subdomain enumeration"),
    Tool("httpx",       "recon", "go", "github.com/projectdiscovery/httpx/cmd/httpx@latest",            check_cmd="httpx -version", description="HTTP liveness & tech probing"),
    Tool("katana",      "recon", "go", "github.com/projectdiscovery/katana/cmd/katana@latest",          check_cmd="katana -version", description="JS-aware web crawler"),
    Tool("nuclei",      "scan",  "go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",       check_cmd="nuclei -version", post_install=["nuclei -update-templates -silent"], description="Template-based vuln scanner"),

    # TomNomNom
    Tool("assetfinder", "recon", "go", "github.com/tomnomnom/assetfinder@latest",  check_cmd="assetfinder --help", description="Subdomain discovery"),
    Tool("waybackurls", "recon", "go", "github.com/tomnomnom/waybackurls@latest",  check_cmd="waybackurls --help", description="Wayback URL miner"),
    Tool("anew",        "util",  "go", "github.com/tomnomnom/anew@latest",         check_cmd="anew --help", description="Append new lines to files"),

    # Fuzzing
    Tool("ffuf",        "recon", "go", "github.com/ffuf/ffuf/v2@latest",           check_cmd="ffuf -V", description="Fast web fuzzer"),
    Tool("feroxbuster", "recon", "go", "github.com/epi052/feroxbuster@latest",     check_cmd="feroxbuster --version", description="Recursive content discovery"),

    # Auditing
    Tool("dalfox",      "audit", "go", "github.com/hahwul/dalfox/v2@latest",       check_cmd="dalfox -version", description="XSS scanner"),

    # OSINT / URL discovery
    Tool("amass",       "recon", "go", "github.com/owasp-amass/amass/v4/...@master", check_cmd="amass -version", description="OSINT subdomain enum"),
    Tool("gau",         "recon", "go", "github.com/lc/gau/v2/cmd/gau@latest",       check_cmd="gau -version", description="GetAllUrls fetcher"),
]

# ── Wordlist resources ───────────────────────────────────────────────────────
RESOURCE_TOOLS = [
    Tool(
        "seclists",
        category="resource",
        method="special",
        package="https://github.com/danielmiessler/SecLists.git",
        sudo=True,
        check_cmd="test -d /usr/share/seclists || test -d /opt/seclists",
        description="Standard wordlist collection",
    ),
]

# Combined lookup
ALL_TOOLS = BASE_PACKAGES + APT_SECURITY_TOOLS + GO_TOOLS + RESOURCE_TOOLS
TOOLS_BY_NAME = {t.name: t for t in ALL_TOOLS}


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG:    C["dim"],
        logging.INFO:     C["reset"],
        logging.WARNING:  C["yellow"],
        logging.ERROR:    C["red"],
        logging.CRITICAL: C["magenta"] + C["bold"],
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.LEVEL_COLORS.get(record.levelno, "")
        msg = record.getMessage()
        return f"{color}{msg}{C['reset']}"


def setup_logging(verbose: bool, no_color: bool) -> logging.Logger:
    LOG_DIR.mkdir(exist_ok=True)
    logger = logging.getLogger("argus-tools")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    if no_color or not sys.stdout.isatty():
        console.setFormatter(logging.Formatter("%(message)s"))
    else:
        console.setFormatter(ColorFormatter())
    logger.addHandler(console)

    logfile = logging.FileHandler(LOG_DIR / "tools.log", mode="a")
    logfile.setLevel(logging.DEBUG)
    logfile.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(logfile)

    return logger


# Global logger — replaced in main()
log = logging.getLogger("argus-tools")


def _c(key: str, text: str) -> str:
    """Wrap text in a color if stdout is a TTY and color is enabled."""
    if not sys.stdout.isatty() or "--no-color" in sys.argv:
        return text
    return f"{C[key]}{text}{C['reset']}"


# ─────────────────────────────────────────────────────────────────────────────
# Shell / subprocess helpers
# ─────────────────────────────────────────────────────────────────────────────

def run(cmd: list[str], sudo: bool = False, timeout: int = 900,
        quiet: bool = False, check: bool = False) -> tuple[bool, str, str]:
    """Run a command, return (success, stdout, stderr)."""
    if sudo and not IS_ROOT:
        cmd = ["sudo"] + cmd

    if not quiet:
        log.debug(f"$ {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if quiet else None,
            stderr=subprocess.PIPE if quiet else None,
            timeout=timeout,
            text=True,
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        ok = result.returncode == 0
        if not ok and check:
            raise subprocess.CalledProcessError(result.returncode, cmd, stdout, stderr)
        return ok, stdout, stderr
    except subprocess.TimeoutExpired:
        return False, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return False, "", f"not found: {e}"
    except Exception as e:
        return False, "", f"unexpected error: {e}"


def cmd_available(binary: str) -> bool:
    """True if `binary` exists on PATH."""
    return shutil.which(binary) is not None


def run_check(check_cmd: str, timeout: int = 10) -> bool:
    """Run a check_cmd shell string (list-split, no shell). Returns True if exit 0."""
    if not check_cmd:
        return False
    try:
        cmd = shlex.split(check_cmd)
    except ValueError:
        return False
    # For python module checks that use -c, we must not split the quoted part
    if " -c " in check_cmd:
        cmd = ["python3", "-c", check_cmd.split(" -c ", 1)[1].strip("'\"")]
    ok, _, _ = run(cmd, timeout=timeout, quiet=True)
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Privilege & environment setup
# ─────────────────────────────────────────────────────────────────────────────

def detect_debian() -> bool:
    """Confirm we're on a Debian-derived distro."""
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return False
    content = os_release.read_text()
    markers = ("debian", "ubuntu", "kali", "parrot", "pop", "mint", "raspbian")
    id_line = next((l for l in content.splitlines() if l.startswith("ID=")), "")
    like_line = next((l for l in content.splitlines() if l.startswith("ID_LIKE=")), "")
    combined = (id_line + " " + like_line).lower()
    return any(m in combined for m in markers)


def cache_sudo() -> bool:
    """Ensure sudo credentials are cached for the session."""
    if IS_ROOT:
        return True
    # Already passwordless?
    ok, _, _ = run(["sudo", "-n", "true"], quiet=True)
    if ok:
        log.debug("sudo: passwordless (cached)")
        return True
    # Prompt once
    log.info(f"  {_c('yellow', '!')} Caching sudo credentials (you may be prompted)...")
    try:
        rc = subprocess.run(["sudo", "-v"]).returncode
        return rc == 0
    except FileNotFoundError:
        return False


def ensure_paths() -> None:
    """Prepend Go binary directories to PATH for this process."""
    additions = [str(GO_BIN_DIR), "/usr/local/go/bin"]
    current = os.environ.get("PATH", "")
    for p in additions:
        if p not in current.split(":"):
            current = f"{p}:{current}"
    os.environ["PATH"] = current


def get_go_version() -> Optional[str]:
    ok, out, _ = run(["go", "version"], quiet=True)
    if not ok:
        return None
    # "go version go1.22.1 linux/amd64"
    parts = out.split()
    return parts[2] if len(parts) >= 3 else out.strip()


# ─────────────────────────────────────────────────────────────────────────────
# Go toolchain installation
# ─────────────────────────────────────────────────────────────────────────────

def latest_go_version() -> Optional[str]:
    """Fetch latest stable Go version from go.dev JSON API."""
    try:
        req = urllib.request.Request(
            "https://go.dev/dl/?mode=json",
            headers={"User-Agent": f"argus-tools/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        for release in data:
            if not release.get("stable", False):
                continue
            return release["version"]  # e.g. "go1.22.1"
    except Exception as e:
        log.debug(f"latest_go_version failed: {e}")
    return None


def install_go() -> bool:
    """Install the Go toolchain to /usr/local/go."""
    version = latest_go_version()
    if not version:
        log.error(f"  {_c('red', '✗')} Could not fetch latest Go version")
        return False

    arch = "amd64" if platform.machine() in ("x86_64", "AMD64") else "arm64"
    tarball = f"{version}.linux-{arch}.tar.gz"
    url = f"https://go.dev/dl/{tarball}"
    tmp_path = Path(f"/tmp/{tarball}")

    log.info(f"  {_c('cyan', '↑')} Downloading {tarball}...")
    ok, _, err = run(
        ["curl", "-fsSL", "-o", str(tmp_path), url],
        timeout=300, quiet=True,
    )
    if not ok:
        log.error(f"  {_c('red', '✗')} Download failed: {err}")
        return False

    log.info(f"  {_c('cyan', '↑')} Extracting to /usr/local/...")
    # Remove any previous installation
    if GO_INSTALL_DIR.exists():
        run(["rm", "-rf", str(GO_INSTALL_DIR)], sudo=True, quiet=True)
    ok, _, err = run(
        ["tar", "-C", "/usr/local", "-xzf", str(tmp_path)],
        sudo=True, quiet=True,
    )
    tmp_path.unlink(missing_ok=True)
    if not ok:
        log.error(f"  {_c('red', '✗')} Extraction failed: {err}")
        return False

    ensure_paths()
    ok, out, _ = run(["go", "version"], quiet=True)
    if ok:
        log.info(f"  {_c('green', '✓')} {out.strip()}")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-method installers
# ─────────────────────────────────────────────────────────────────────────────

def install_apt(tool: Tool) -> bool:
    """Install via apt-get."""
    ok, _, err = run(
        ["apt-get", "install", "-y", "-q", tool.package],
        sudo=True, timeout=600, quiet=True,
    )
    if not ok:
        log.debug(f"apt install {tool.package} stderr: {err}")
    return ok


def install_go_tool(tool: Tool) -> bool:
    """Install via `go install`."""
    # Ensure go is on PATH
    ensure_paths()
    if not cmd_available("go"):
        log.error(f"  {_c('red', '✗')} go compiler missing — cannot install {tool.name}")
        return False

    ok, _, err = run(
        ["go", "install", tool.package],
        timeout=600, quiet=True,
    )
    if not ok:
        log.debug(f"go install {tool.package} stderr: {err}")
        return False

    # Verify binary landed in $GOPATH/bin
    binary_path = GO_BIN_DIR / tool.resolved_binary
    if binary_path.exists():
        return True
    # Some tools have a different binary name — check via which
    return cmd_available(tool.resolved_binary)


def install_git(tool: Tool) -> bool:
    """Clone a repo into /opt/<name>."""
    dest = Path("/opt") / tool.name
    if dest.exists():
        return True
    parent_sudo = not IS_ROOT
    # /opt requires sudo
    ok, _, err = run(
        ["git", "clone", "--depth", "1", tool.package, str(dest)],
        sudo=parent_sudo, timeout=900, quiet=True,
    )
    if not ok:
        log.debug(f"git clone {tool.package} stderr: {err}")
    return ok


def install_seclists(tool: Tool) -> bool:
    """Try apt package; fall back to git clone into /opt."""
    # 1. Try apt
    ok, _, _ = run(
        ["apt-get", "install", "-y", "-q", "seclists"],
        sudo=True, timeout=600, quiet=True,
    )
    if ok and any(p.exists() for p in SECLISTS_PATHS):
        return True

    # 2. Fall back to git clone
    log.info(f"  {_c('cyan', '↑')} apt seclists unavailable — cloning to /opt/seclists...")
    return install_git(
        Tool("seclists", "resource", "git",
             "https://github.com/danielmiessler/SecLists.git", sudo=True)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Install driver
# ─────────────────────────────────────────────────────────────────────────────

def is_installed(tool: Tool) -> bool:
    """Check whether a tool is already installed."""
    # 1. Explicit check command
    if tool.check_cmd:
        return run_check(tool.check_cmd)

    # 2. Binary lookup
    if tool.method in ("apt", "go"):
        return cmd_available(tool.resolved_binary)

    # 3. Directory existence (git / special)
    if tool.method == "git":
        return (Path("/opt") / tool.name).exists()

    return False


def install_tool(tool: Tool, dry_run: bool, assume_yes: bool) -> str:
    """
    Install a single tool. Returns one of: 'present', 'installed', 'failed', 'skipped'.
    """
    if is_installed(tool):
        return "present"

    if dry_run:
        log.info(f"  {_c('dim', '→')} {tool.name:<14} {_c('dim', '[dry-run: would install]')}")
        return "skipped"

    log.info(f"  {_c('cyan', '↑')} {tool.name:<14} installing...")

    if tool.method == "apt":
        ok = install_apt(tool)
    elif tool.method == "go":
        ok = install_go_tool(tool)
    elif tool.method == "git":
        ok = install_git(tool)
    elif tool.method == "special" and tool.name == "seclists":
        ok = install_seclists(tool)
    else:
        log.error(f"  {_c('red', '✗')} {tool.name:<14} unknown method: {tool.method}")
        return "failed"

    if not ok:
        log.error(f"  {_c('red', '✗')} {tool.name:<14} install FAILED")
        return "failed"

    # Post-install hooks (e.g. nuclei -update-templates)
    for hook in tool.post_install:
        h_ok, _, h_err = run(shlex.split(hook), timeout=300, quiet=True)
        if not h_ok:
            log.warning(f"  {_c('yellow', '!')} {tool.name:<14} post-install hook failed: {hook}")

    # Verify
    if not is_installed(tool):
        log.error(f"  {_c('red', '✗')} {tool.name:<14} install returned OK but verification failed")
        return "failed"

    log.info(f"  {_c('green', '✓')} {tool.name:<14} installed")
    return "installed"


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────────────────

def header() -> None:
    os_name = "unknown"
    try:
        os_name = platform.freedesktop_os_release().get("PRETTY_NAME", "Debian")
    except Exception:
        pass
    bar = _c("cyan", "═" * 62)
    log.info(bar)
    log.info(f"  {_c('bold', 'ARGUS')} // tools.py v{VERSION} — dependency installer")
    log.info(f"  {os_name} / Python {platform.python_version()} / user: {os.environ.get('USER', '?')}")
    log.info(bar)
    log.info("")


def section(n: int, total: int, title: str) -> None:
    log.info("")
    log.info(f"{_c('cyan', f'[{n}/{total}]')} {_c('bold', title)}")


def main() -> int:
    global log

    parser = argparse.ArgumentParser(
        prog="tools.py",
        description="Argus dependency installer for Debian-based systems.",
    )
    parser.add_argument("--check", action="store_true", help="Check only; no installs")
    parser.add_argument("--dry-run", action="store_true", help="Show plan, change nothing")
    parser.add_argument("--yes", action="store_true", help="Assume yes; no prompts")
    parser.add_argument("--category", help="Comma-separated categories: base,recon,scan,audit,util,resource")
    parser.add_argument("--only", help="Comma-separated tool names to install (overrides category)")
    parser.add_argument("--skip", help="Comma-separated tool names to skip")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    log = setup_logging(args.verbose, args.no_color)

    # ── Pre-flight ──────────────────────────────────────────────────────────
    header()

    section(1, 6, "Pre-flight checks")
    if not detect_debian():
        log.error(f"  {_c('red', '✗')} Not a Debian-based system. Aborting.")
        return 2
    log.info(f"  {_c('green', '✓')} Debian-based system")

    if not IS_ROOT:
        if not shutil.which("sudo"):
            log.error(f"  {_c('red', '✗')} sudo not found and not running as root")
            return 2
        if not args.dry_run and not args.check:
            if not cache_sudo():
                log.error(f"  {_c('red', '✗')} sudo authentication failed")
                return 2
        log.info(f"  {_c('green', '✓')} sudo available")
    else:
        log.info(f"  {_c('green', '✓')} running as root")

    log.info(f"  {_c('green', '✓')} Python {platform.python_version()}")

    # Ensure PATH includes Go bin dirs from the start
    ensure_paths()

    # ── Tool selection ──────────────────────────────────────────────────────
    selected: list[Tool] = []
    if args.only:
        wanted = {x.strip() for x in args.only.split(",") if x.strip()}
        selected = [t for t in ALL_TOOLS if t.name in wanted]
        missing = wanted - {t.name for t in selected}
        if missing:
            log.warning(f"  {_c('yellow', '!')} Unknown tools: {', '.join(sorted(missing))}")
    elif args.category:
        cats = {x.strip() for x in args.category.split(",") if x.strip()}
        selected = [t for t in ALL_TOOLS if t.category in cats]
    else:
        selected = list(ALL_TOOLS)

    if args.skip:
        skip_set = {x.strip() for x in args.skip.split(",") if x.strip()}
        selected = [t for t in selected if t.name not in skip_set]

    if not selected:
        log.error("No tools selected. Check your --only/--category/--skip filters.")
        return 2

    log.info(f"  {_c('dim', 'Selected')}: {len(selected)} tool(s)")

    # ── Check-only mode ─────────────────────────────────────────────────────
    if args.check:
        section(2, 2, "Tool status")
        missing_count = 0
        for t in selected:
            if is_installed(t):
                log.info(f"  {_c('green', '✓')} {t.name:<14} present")
            else:
                log.info(f"  {_c('red', '✗')} {t.name:<14} MISSING")
                missing_count += 1
        log.info("")
        if missing_count:
            log.warning(f"{missing_count} tool(s) missing.")
            return 1
        log.info(f"{_c('green', 'All tools present.')}")
        return 0

    # ── apt update ─────────────────────────────────────────────────────────
    section(2, 6, "Refresh package index")
    if args.dry_run:
        log.info(f"  {_c('dim', '→')} [dry-run] sudo apt-get update")
    else:
        ok, _, err = run(["apt-get", "update", "-q"], sudo=True, timeout=300, quiet=True)
        if ok:
            log.info(f"  {_c('green', '✓')} apt-get update complete")
        else:
            log.warning(f"  {_c('yellow', '!')} apt-get update failed (continuing anyway)")
            log.debug(err)

    # ── Base packages ──────────────────────────────────────────────────────
    section(3, 6, "Base dependencies")
    base = [t for t in selected if t.category == "base"]
    if base:
        for t in base:
            install_tool(t, args.dry_run, args.yes)
    else:
        log.info(f"  {_c('dim', '(none selected)')}")

    # ── Go toolchain ───────────────────────────────────────────────────────
    section(4, 6, "Go toolchain")
    go_tools_selected = [t for t in selected if t.method == "go"]
    if go_tools_selected:
        go_version = get_go_version()
        if go_version:
            log.info(f"  {_c('green', '✓')} {go_version} already installed")
        else:
            log.info(f"  {_c('cyan', '↑')} go compiler not found — installing...")
            if args.dry_run:
                log.info(f"  {_c('dim', '→')} [dry-run] would install Go toolchain")
            else:
                if install_go():
                    log.info(f"  {_c('green', '✓')} go toolchain installed")
                else:
                    log.error(f"  {_c('red', '✗')} Go installation failed — Go tools cannot be installed")
                    go_tools_selected = []

    # ── Security tools ─────────────────────────────────────────────────────
    section(5, 6, "Security tools")
    stats = {"present": 0, "installed": 0, "failed": 0, "skipped": 0}

    non_base = [t for t in selected if t.category != "base"]
    for t in non_base:
        # Skip Go tools if Go install failed
        if t.method == "go" and not cmd_available("go"):
            log.warning(f"  {_c('yellow', '!')} {t.name:<14} skipped (go missing)")
            stats["skipped"] += 1
            continue
        # Count base results too
        result = install_tool(t, args.dry_run, args.yes)
        stats[result] += 1

    # Also count base results
    for t in base:
        if is_installed(t):
            stats["present"] += 1

    # ── Summary ────────────────────────────────────────────────────────────
    section(6, 6, "Summary")
    log.info(f"  {_c('green', '✓')} Present:    {stats['present']}")
    log.info(f"  {_c('cyan',  '↑')} Installed:  {stats['installed']}")
    if stats["skipped"]:
        log.info(f"  {_c('dim',   '·')} Skipped:    {stats['skipped']}")
    if stats["failed"]:
        log.info(f"  {_c('red',   '✗')} Failed:     {stats['failed']}")

    # ── PATH persistence hint ──────────────────────────────────────────────
    if not args.dry_run and stats["installed"] > 0:
        go_path_line = f'export PATH="{GO_BIN_DIR}:/usr/local/go/bin:$PATH"'
        log.info("")
        log.info(f"  {_c('yellow', '!')} Persist Go binaries to your shell PATH:")
        log.info(f"    {_c('dim', 'echo ' + repr(go_path_line) + ' >> ~/.bashrc')}")
        log.info(f"    {_c('dim', 'source ~/.bashrc')}")
        log.info(f"  {_c('dim', '(Current session already includes these paths.)')}")

    log.info("")
    log.info(_c("cyan", "═" * 62))
    log.info(f"  Log: {LOG_DIR / 'tools.log'}")
    log.info(_c("cyan", "═" * 62))

    return 0 if stats["failed"] == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C['yellow']}Interrupted by user.{C['reset']}")
        sys.exit(130)
