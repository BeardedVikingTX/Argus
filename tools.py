#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  ᛊ ᛗ ᛁ ᛞ ᚱ   ·   T O O L S   ·   T H E   S M I T H
================================================================================
  File      : tools.py
  Version   : 3.1.0 "SMIDR REBORN"
  Author    : BeardedVikingTX  ·  security@beardedviking.org
  License   : MIT

  Cross-platform dependency smith for Argus.

  Supported platforms
  ───────────────────
    ·  Linux    — Debian/Ubuntu/Kali/Parrot/Mint/Pop (apt), Fedora/RHEL (dnf),
                  Arch/BlackArch (pacman), openSUSE (zypper), Alpine (apk)
    ·  macOS    — Intel + Apple Silicon (Homebrew)
    ·  Windows  — 10 / 11 (winget primary, Scoop fallback, Chocolatey last resort)
    ·  Termux   — Android terminal (pkg, no sudo, aarch64/arm)
    ·  NetHunter— Termux + Kali chroot (detects and uses kali-* wrappers)

  Design principles
  ──────────────────
    ·  Idempotent     — rerun-safe; only installs what's missing
    ·  Verifiable     — every install confirmed by a post-install probe
    ·  Lightweight    — detects CPU/RAM/disk and throttles heavy compiles
    ·  Deterministic  — every tool has a known install method per platform
    ·  Fail-soft      — a missing tool on one platform does not abort the run
    ·  Self-testing   — `--selftest` verifies every critical function exists
    ·  Theme-aware    — runes + 256-color palette (matches config.py)

  Usage
  ─────
    python3 tools.py                     # install everything for this platform
    python3 tools.py --check             # verify only, exit 1 if missing
    python3 tools.py --dry-run           # show plan, change nothing
    python3 tools.py --selftest          # verify script integrity
    python3 tools.py --diagnose gau      # deep-dive a single tool
    python3 tools.py --only nuclei,httpx --force
================================================================================
"""

from __future__ import annotations

# ─── stdlib only ───────────────────────────────────────────────────────────
import argparse
import json
import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


# ══════════════════════════════════════════════════════════════════════════
#  ᛖ  METADATA
# ══════════════════════════════════════════════════════════════════════════

__version__ = "3.2.0"
__codename__ = "SMIDR RECON"
VERSION = __version__

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = OUTPUT_DIR
TOOLS_LOG = LOG_DIR / "tools.log"


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  THEME
# ══════════════════════════════════════════════════════════════════════════

class Rune:
    FEHU = "ᚠ"; URUZ = "ᚢ"; THURISAZ = "ᚦ"; ANSUZ = "ᚨ"; RAIDO = "ᚱ"
    KANO = "ᚲ"; GEBO = "ᚷ"; WUNJO = "ᚹ"; HAGALAZ = "ᚺ"; NAUTHIZ = "ᚾ"
    ISA = "ᛁ"; JERA = "ᛃ"; EIHWAZ = "ᛇ"; PERTHRO = "ᛈ"; ALGIZ = "ᛉ"
    SOWILO = "ᛊ"; TIWAZ = "ᛏ"; BERKANO = "ᛒ"; EHWAZ = "ᛖ"; MANNAZ = "ᛗ"
    LAGUZ = "ᛚ"; INGWAZ = "ᛜ"; DAGAZ = "ᛞ"; OTHALA = "ᛟ"


class Sym:
    RAVEN = "🦅"; WOLF = "🐺"; SHIELD = "🛡"; SWORD = "⚔"; HAMMER = "🔨"
    TREE = "🌳"; FIRE = "🔥"; SHAMROCK = "☘"; STAR = "★"; ARROW = "➤"
    CHECK = "✓"; CROSS = "✗"; WARN = "⚠"; INFO = "·"; DOT = "᛫"
    SKULL = "☠"; LOCK = "🔒"; GEAR = "⚙"


class Palette:
    _enabled = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
    _rich = ("256" in os.getenv("TERM", "")) or os.getenv("COLORTERM") in ("truecolor", "24bit")
    _R = {
        "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
        "gold": "\033[38;5;220m", "amber": "\033[38;5;214m",
        "purple": "\033[38;5;135m", "violet": "\033[38;5;93m",
        "crimson": "\033[38;5;160m", "blood": "\033[38;5;196m",
        "green": "\033[38;5;46m", "moss": "\033[38;5;118m",
        "blue": "\033[38;5;33m", "cyan": "\033[38;5;51m",
        "ice": "\033[38;5;159m", "grey": "\033[38;5;242m",
        "silver": "\033[38;5;250m", "orange": "\033[38;5;208m",
        "pink": "\033[38;5;213m",
    }
    _B = {
        "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
        "gold": "\033[33m", "amber": "\033[33m", "purple": "\033[35m",
        "violet": "\033[35m", "crimson": "\033[31m", "blood": "\033[91m",
        "green": "\033[32m", "moss": "\033[92m", "blue": "\033[34m",
        "cyan": "\033[36m", "ice": "\033[96m", "grey": "\033[90m",
        "silver": "\033[37m", "orange": "\033[33m", "pink": "\033[95m",
    }

    @classmethod
    def c(cls, name: str) -> str:
        if not cls._enabled:
            return ""
        return (cls._R if cls._rich else cls._B).get(name, "")


def _c(name: str) -> str:
    return Palette.c(name)


def print_banner() -> None:
    G, P, V, D, R = _c("gold"), _c("purple"), _c("violet"), _c("dim"), _c("reset")
    rule = "═" * 66
    print(f"""
    {G}ᛊ ᛗ ᛁ ᛞ ᚱ{R}
    {P}{rule}{R}
    {V}          T O O L S   ·   T H E   S M I T H{R}
    {V}              F O R G I N G   A R G U S{R}
    {D}{rule}{R}
    {G}        {Sym.HAMMER}  v{__version__} "{__codename__}"  ·  cross-platform{R}
    {G}        {Sym.GEAR}  {platform.system()} {platform.release()}  ·  {platform.machine()}{R}
    {G}        {Sym.SHAMROCK}  BeardedVikingTX  ·  security@beardedviking.org{R}
    {P}{rule}{R}
""")


# ══════════════════════════════════════════════════════════════════════════
#  ᛚ  LOGGER
# ══════════════════════════════════════════════════════════════════════════

class ArgusLogger:
    _LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "fatal": 50}

    def __init__(self, name: str = "tools", log_file: Optional[Path] = None,
                 min_level: str = "info"):
        self.name = name
        self.min_level = min_level
        self._log = logging.getLogger(name)
        self._log.setLevel(logging.DEBUG)
        self._log.propagate = False
        if self._log.handlers:
            self._log.handlers.clear()
        if log_file:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                fh = logging.FileHandler(log_file, encoding="utf-8")
                fh.setLevel(logging.DEBUG)
                fh.setFormatter(logging.Formatter(
                    "%(asctime)s [%(levelname)-8s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"))
                self._log.addHandler(fh)
            except OSError:
                pass

    def _emit(self, level: str, msg: str, color: str, prefix: str) -> None:
        if self._LEVELS.get(level, 20) >= self._LEVELS.get(self.min_level, 20):
            print(f"  {_c(color)}{prefix}{_c('reset')} {msg}")
        method = {"warn": "warning", "fatal": "critical"}.get(level, level)
        getattr(self._log, method, self._log.info)(msg)

    def debug(self, m): self._emit("debug", m, "grey", Sym.DOT)
    def info(self, m): self._emit("info", m, "cyan", Sym.INFO)
    def warn(self, m): self._emit("warn", m, "amber", Sym.WARN)
    def error(self, m): self._emit("error", m, "crimson", Sym.CROSS)
    def fatal(self, m): self._emit("fatal", m, "blood", Sym.SKULL)
    def ok(self, m): self._emit("info", m, "green", Sym.CHECK)

    def rune(self, rune: str, msg: str) -> None:
        print(f"\n{_c('violet')}── {rune}  {msg} ──{_c('reset')}")
        self._log.info(f"[{rune}] {msg}")


log = ArgusLogger("tools", TOOLS_LOG)


# ══════════════════════════════════════════════════════════════════════════
#  ᛖ  PLATFORM DETECTION
# ══════════════════════════════════════════════════════════════════════════

class PlatformKind:
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    TERMUX = "termux"
    NETHUNTER = "nethunter"


@dataclass(frozen=True)
class PlatformInfo:
    kind: str
    distro_id: str = ""
    distro_like: str = ""
    arch: str = ""
    is_root: bool = False
    has_sudo: bool = False
    shell: str = ""

    @property
    def is_debian(self) -> bool:
        return self.kind == PlatformKind.LINUX and self.distro_id in (
            "debian", "ubuntu", "kali", "parrot", "linuxmint", "pop", "raspbian")

    @property
    def is_arch(self) -> bool:
        return self.kind == PlatformKind.LINUX and self.distro_id in ("arch", "blackarch", "manjaro")

    @property
    def is_fedora(self) -> bool:
        return self.kind == PlatformKind.LINUX and self.distro_id in ("fedora", "rhel", "centos", "rocky", "almalinux")

    @property
    def is_alpine(self) -> bool:
        return self.kind == PlatformKind.LINUX and self.distro_id == "alpine"

    @property
    def is_android(self) -> bool:
        return self.kind in (PlatformKind.TERMUX, PlatformKind.NETHUNTER)


def detect_platform() -> PlatformInfo:
    system = platform.system().lower()
    arch = platform.machine().lower()

    if system == "windows":
        return PlatformInfo(PlatformKind.WINDOWS, arch=arch,
                            is_root=False, has_sudo=False,
                            shell=os.getenv("COMSPEC", "cmd.exe"))

    if system == "darwin":
        return PlatformInfo(PlatformKind.MACOS, arch=arch,
                            is_root=os.geteuid() == 0, has_sudo=True,
                            shell=os.getenv("SHELL", "/bin/zsh"))

    if "com.termux" in os.getenv("PREFIX", ""):
        if shutil.which("kali") or Path("/data/data/com.offsec.nethunter").exists():
            return PlatformInfo(PlatformKind.NETHUNTER, arch=arch,
                                is_root=False, has_sudo=False,
                                shell="/system/bin/sh")
        return PlatformInfo(PlatformKind.TERMUX, arch=arch,
                            is_root=False, has_sudo=False,
                            shell="/system/bin/sh")

    distro_id, distro_like = "", ""
    osr = Path("/etc/os-release")
    if osr.exists():
        text = osr.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^ID="?([^"\n]+)"?', text, re.M)
        if m:
            distro_id = m.group(1).lower()
        m = re.search(r'^ID_LIKE="?([^"\n]+)"?', text, re.M)
        if m:
            distro_like = m.group(1).lower()

    return PlatformInfo(
        PlatformKind.LINUX, distro_id=distro_id, distro_like=distro_like,
        arch=arch, is_root=os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        has_sudo=shutil.which("sudo") is not None,
        shell=os.getenv("SHELL", "/bin/sh"),
    )


PLATFORM = detect_platform()


# ══════════════════════════════════════════════════════════════════════════
#  ᚲ  PACKAGE MANAGER DETECTION
# ══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class PackageManager:
    name: str
    install_cmd: list[str]
    update_cmd: Optional[list[str]] = None
    needs_sudo: bool = True


def detect_package_manager(p: PlatformInfo = PLATFORM) -> Optional[PackageManager]:
    if p.kind == PlatformKind.WINDOWS:
        if shutil.which("winget"):
            return PackageManager(
                name="winget",
                install_cmd=["winget", "install", "--silent",
                             "--accept-package-agreements",
                             "--accept-source-agreements"],
                update_cmd=None, needs_sudo=False)
        if shutil.which("scoop"):
            return PackageManager(name="scoop", install_cmd=["scoop", "install"],
                                  needs_sudo=False)
        if shutil.which("choco"):
            return PackageManager(name="choco", install_cmd=["choco", "install", "-y"],
                                  needs_sudo=True)
        return None

    if p.kind == PlatformKind.MACOS:
        if shutil.which("brew"):
            return PackageManager(name="brew", install_cmd=["brew", "install"],
                                  update_cmd=["brew", "update"], needs_sudo=False)
        return None

    if p.kind in (PlatformKind.TERMUX, PlatformKind.NETHUNTER):
        if shutil.which("pkg"):
            return PackageManager(name="pkg", install_cmd=["pkg", "install", "-y"],
                                  update_cmd=["pkg", "update", "-y"], needs_sudo=False)
        return None

    if p.is_debian and shutil.which("apt-get"):
        return PackageManager(name="apt", install_cmd=["apt-get", "install", "-y", "-q"],
                              update_cmd=["apt-get", "update", "-q"], needs_sudo=True)
    if p.is_fedora and shutil.which("dnf"):
        return PackageManager(name="dnf", install_cmd=["dnf", "install", "-y", "-q"],
                              update_cmd=["dnf", "makecache", "-q"], needs_sudo=True)
    if p.is_arch and shutil.which("pacman"):
        return PackageManager(name="pacman",
                              install_cmd=["pacman", "-S", "--noconfirm", "--needed"],
                              update_cmd=["pacman", "-Sy"], needs_sudo=True)
    if p.distro_id in ("opensuse", "suse", "sles") and shutil.which("zypper"):
        return PackageManager(name="zypper", install_cmd=["zypper", "install", "-y"],
                              update_cmd=["zypper", "refresh"], needs_sudo=True)
    if p.is_alpine and shutil.which("apk"):
        return PackageManager(name="apk", install_cmd=["apk", "add"],
                              update_cmd=["apk", "update"], needs_sudo=True)

    for candidate in ("apt-get", "dnf", "pacman", "zypper", "apk"):
        if shutil.which(candidate):
            return PackageManager(candidate, [candidate, "install", "-y"], needs_sudo=True)
    return None


PKG = detect_package_manager()


# ══════════════════════════════════════════════════════════════════════════
#  ᛏ  HOST CAPACITY / LIGHTWEIGHT GUARD
# ══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class HostCapacity:
    cpu_cores: int
    ram_mb: int
    disk_free_mb: int
    is_lightweight: bool
    reason: str = ""


def measure_host() -> HostCapacity:
    cores = os.cpu_count() or 1
    ram_mb = 0
    disk_mb = 0

    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        ram_mb = int(line.split()[1]) // 1024
                        break
        elif platform.system() == "Darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                                 capture_output=True, text=True).stdout
            ram_mb = int(out.strip()) // (1024 * 1024) if out.strip() else 0
        elif platform.system() == "Windows":
            out = subprocess.run(
                ["wmic", "ComputerSystem", "get", "TotalPhysicalMemory"],
                capture_output=True, text=True).stdout
            nums = re.findall(r"\d+", out)
            if nums:
                ram_mb = int(nums[-1]) // (1024 * 1024)
    except Exception:
        pass

    try:
        usage = shutil.disk_usage(BASE_DIR)
        disk_mb = usage.free // (1024 * 1024)
    except Exception:
        pass

    reasons = []
    if cores <= 2:
        reasons.append(f"{cores} CPU cores")
    if ram_mb and ram_mb < 2048:
        reasons.append(f"{ram_mb} MB RAM")
    if disk_mb and disk_mb < 2048:
        reasons.append(f"{disk_mb} MB free disk")

    return HostCapacity(
        cpu_cores=cores, ram_mb=ram_mb, disk_free_mb=disk_mb,
        is_lightweight=bool(reasons),
        reason=", ".join(reasons) if reasons else "sufficient capacity",
    )


HOST = measure_host()
LIGHTWEIGHT_MODE = HOST.is_lightweight or os.getenv("ARGUS_LIGHTWEIGHT") == "1"


# ══════════════════════════════════════════════════════════════════════════
#  ᛒ  COMMAND RUNNERS  ·  cmd_available, run, run_check
# ══════════════════════════════════════════════════════════════════════════
#  These MUST be defined before anything that calls them at import time.
#  This section was missing in the previous revision — the exact bug that
#  produced `NameError: name 'cmd_available' is not defined`.
# ══════════════════════════════════════════════════════════════════════════

def cmd_available(binary: str) -> bool:
    """True if `binary` exists on PATH."""
    return shutil.which(binary) is not None


def run(cmd: list[str], sudo: bool = False, timeout: int = 900,
        quiet: bool = False) -> tuple[bool, str, str]:
    """
    Run a command. Sudo handling:
      · cached        → `sudo -n` (fast, non-interactive)
      · not cached    → `sudo` (prompts via /dev/tty)
    """
    if sudo and PLATFORM.has_sudo and not PLATFORM.is_root:
        cmd = (["sudo", "-n"] if _sudo_available() else ["sudo"]) + cmd

    if not quiet:
        log.debug(f"$ {' '.join(cmd)}")

    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=False,
        )
        return res.returncode == 0, res.stdout or "", res.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return False, "", f"not found: {e}"
    except Exception as e:
        return False, "", f"{type(e).__name__}: {e}"


def run_check(check_cmd: str, timeout: int = 10) -> bool:
    """
    Run a check command. Uses a shell when shell operators are present,
    so `test -d /a || test -d /b` actually works.
    """
    if not check_cmd:
        return False
    if any(ch in check_cmd for ch in "|&;()<>"):
        if os.name == "nt":
            cmd = ["cmd", "/c", check_cmd]
        else:
            cmd = ["/bin/sh", "-c", check_cmd]
    else:
        try:
            cmd = shlex.split(check_cmd)
        except ValueError:
            return False
    ok, _, _ = run(cmd, timeout=timeout, quiet=True)
    return ok


# ══════════════════════════════════════════════════════════════════════════
#  ᛉ  SUDO HANDLING
# ══════════════════════════════════════════════════════════════════════════

_SUDO_CACHED: Optional[bool] = None
_SUDO_LOCK = threading.Lock()


def _sudo_available() -> bool:
    """Non-blocking check: are sudo credentials currently cached?"""
    global _SUDO_CACHED
    with _SUDO_LOCK:
        if _SUDO_CACHED is not None:
            return _SUDO_CACHED
    try:
        result = subprocess.run(["sudo", "-n", "true"],
                                capture_output=True, timeout=5)
        cached = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        cached = False
    with _SUDO_LOCK:
        _SUDO_CACHED = cached
    return cached


def ensure_sudo(interactive: bool = True) -> bool:
    """
    Ensure sudo credentials are cached for this session.
    Runs `sudo -v` which prompts via /dev/tty.
    """
    global _SUDO_CACHED
    if PLATFORM.is_root:
        _SUDO_CACHED = True
        return True
    if not PLATFORM.has_sudo:
        return False
    if _sudo_available():
        return True
    if not interactive:
        return False

    log.warn("sudo credentials needed — you may be prompted")
    try:
        result = subprocess.run(["sudo", "-v"], timeout=180)
        ok = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.error(f"sudo prompt failed: {type(e).__name__}: {e}")
        ok = False
    with _SUDO_LOCK:
        _SUDO_CACHED = ok
    if ok:
        log.ok("sudo credentials cached")
    return ok


# ══════════════════════════════════════════════════════════════════════════
#  ᚷ  GO / CARGO PATH RESOLUTION
# ══════════════════════════════════════════════════════════════════════════

def go_bin_dir() -> Path:
    ok, out, _ = run(["go", "env", "GOBIN"], quiet=True)
    if ok and out.strip():
        return Path(out.strip())
    ok, out, _ = run(["go", "env", "GOPATH"], quiet=True)
    if ok and out.strip():
        return Path(out.strip().split(os.pathsep)[0]) / "bin"
    return Path.home() / "go" / "bin"


def cargo_bin_dir() -> Path:
    cargo_home = os.environ.get("CARGO_HOME")
    if cargo_home:
        return Path(cargo_home).expanduser() / "bin"
    return Path.home() / ".cargo" / "bin"


def ensure_paths() -> None:
    """Prepend Go/Cargo/local-bin dirs to PATH for this process if applicable."""
    additions: list[str] = []
    if cmd_available("go"):
        additions.append(str(go_bin_dir()))
    if cmd_available("cargo"):
        additions.append(str(cargo_bin_dir()))
    # ~/.local/bin — user-space install target (findomain fallback, future tools)
    local_bin = Path.home() / ".local" / "bin"
    if local_bin.exists():
        additions.append(str(local_bin))
    current = os.environ.get("PATH", "")
    for p in additions:
        if p and p not in current.split(os.pathsep):
            current = f"{p}{os.pathsep}{current}"
    os.environ["PATH"] = current


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  TOOL REGISTRY
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class Tool:
    name: str
    category: str
    binary: Optional[str] = None
    check_cmd: Optional[str] = None
    post_install: list[str] = field(default_factory=list)
    description: str = ""
    methods: dict[str, Any] = field(default_factory=dict)
    sudo: bool = True

    @property
    def resolved_binary(self) -> str:
        return self.binary or self.name


BASE_TOOLS = [
    Tool("git", "base", methods={
        "linux": ("pkg", "git"), "macos": ("brew", "git"),
        "windows": ("winget", "Git.Git"), "termux": ("pkg", "git"),
        "nethunter": ("pkg", "git")},
        check_cmd="git --version", description="Version control"),
    Tool("curl", "base", methods={
        "linux": ("pkg", "curl"), "macos": ("brew", "curl"),
        "windows": ("winget", "cURL.cURL"), "termux": ("pkg", "curl"),
        "nethunter": ("pkg", "curl")},
        check_cmd="curl --version", description="HTTP client"),
    Tool("unzip", "base", methods={
        "linux": ("pkg", "unzip"), "macos": ("brew", "unzip"),
        "windows": ("winget", "GnuWin32.UnZip"), "termux": ("pkg", "unzip"),
        "nethunter": ("pkg", "unzip")},
        check_cmd="unzip -v", description="Archive extractor"),
    Tool("jq", "base", methods={
        "linux": ("pkg", "jq"), "macos": ("brew", "jq"),
        "windows": ("winget", "jqlang.jq"), "termux": ("pkg", "jq"),
        "nethunter": ("pkg", "jq")},
        check_cmd="jq --version", description="JSON processor"),
    Tool("python3", "base", methods={
        "linux": ("pkg", "python3"), "macos": ("brew", "python@3.12"),
        "windows": ("winget", "Python.Python.3.12"), "termux": ("pkg", "python"),
        "nethunter": ("pkg", "python")},
        check_cmd="python3 --version", description="Python interpreter"),
]


SECURITY_TOOLS = [
    Tool("nmap", "scan", methods={
        "linux": ("pkg", "nmap"), "macos": ("brew", "nmap"),
        "windows": ("winget", "Insecure.Nmap"), "termux": ("pkg", "nmap"),
        "nethunter": ("pkg", "nmap")},
        check_cmd="nmap --version", description="Port & service scanner"),
    Tool("sqlmap", "audit", methods={
        "linux": ("pkg", "sqlmap"), "macos": ("brew", "sqlmap"),
        "windows": ("winget", "sqlmapproject.sqlmap"),
        "termux": ("pkg", "sqlmap"), "nethunter": ("pkg", "sqlmap")},
        check_cmd="sqlmap --version", description="SQL injection scanner"),
    Tool("nikto", "scan", methods={
        "linux": ("pkg", "nikto"), "macos": ("brew", "nikto"),
        "windows": ("scoop", "nikto"), "termux": ("pkg", "nikto"),
        "nethunter": ("pkg", "nikto")},
        check_cmd="nikto -Version", description="Web server scanner"),
    Tool("gobuster", "recon", methods={
        "linux": ("pkg", "gobuster"), "macos": ("brew", "gobuster"),
        "windows": ("go", "github.com/OJ/gobuster/v3@latest"),
        "termux": ("pkg", "gobuster"), "nethunter": ("pkg", "gobuster")},
        check_cmd="gobuster version", description="Dir/DNS/vhost busting"),
    Tool("feroxbuster", "recon", methods={
        "linux": ("cargo", "feroxbuster"), "macos": ("brew", "feroxbuster"),
        "windows": ("cargo", "feroxbuster"), "termux": ("pkg", "feroxbuster"),
        "nethunter": ("pkg", "feroxbuster")},
        check_cmd="feroxbuster --version", description="Recursive content discovery"),
    Tool("findomain", "recon", methods={
        "linux":     ("special", "findomain_binary"),
        "macos":     ("special", "findomain_binary"),
        "windows":   ("special", "findomain_binary"),
        "termux":    ("cargo", "findomain"),   # no ARM binary in releases
        "nethunter": ("cargo", "findomain")},
        check_cmd="findomain --version",
        description="Rust-based passive subdomain discovery"),
    Tool("dalfox", "audit", methods={
        "linux": ("cargo", "dalfox"), "macos": ("brew", "dalfox"),
        "windows": ("go", "github.com/hahwul/dalfox/v2@latest"),
        "termux": ("go", "github.com/hahwul/dalfox/v2@latest"),
        "nethunter": ("go", "github.com/hahwul/dalfox/v2@latest")},
        check_cmd="dalfox version", description="XSS scanner"),
]


GO_TOOLS = [
    Tool("subfinder", "recon",
         methods={"*": ("go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")},
         check_cmd="subfinder -version", description="Passive subdomain enum"),
    Tool("httpx", "recon",
         methods={"*": ("go", "github.com/projectdiscovery/httpx/cmd/httpx@latest")},
         check_cmd="httpx -version", description="HTTP liveness & tech probing"),
    Tool("katana", "recon",
         methods={"*": ("go", "github.com/projectdiscovery/katana/cmd/katana@latest")},
         check_cmd="katana -version", description="JS-aware web crawler"),
    Tool("nuclei", "scan",
         methods={"*": ("go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")},
         check_cmd="nuclei -version", post_install=["nuclei -update-templates -silent"],
         description="Template-based vuln scanner"),
    Tool("assetfinder", "recon",
         methods={"*": ("go", "github.com/tomnomnom/assetfinder@latest")},
         check_cmd="assetfinder --help", description="Subdomain discovery"),
    Tool("waybackurls", "recon",
         methods={"*": ("go", "github.com/tomnomnom/waybackurls@latest")},
         check_cmd="waybackurls --help", description="Wayback URL miner"),
    Tool("anew", "util",
         methods={"*": ("go", "github.com/tomnomnom/anew@latest")},
         check_cmd="anew --help", description="Append new lines to files"),
    Tool("ffuf", "recon",
         methods={"*": ("go", "github.com/ffuf/ffuf/v2@latest")},
         check_cmd="ffuf -V", description="Fast web fuzzer"),
    Tool("gau", "recon",
         methods={"*": ("go", "github.com/lc/gau/v2/cmd/gau@latest")},
         check_cmd="gau --version", description="GetAllUrls fetcher"),
]


RESOURCE_TOOLS = [
    Tool("seclists", "resource", check_cmd="test -d /usr/share/seclists",
         methods={"linux": ("special", "seclists_debian"),
                  "macos": ("special", "seclists_brew"),
                  "termux": ("special", "seclists_termux"),
                  "nethunter": ("special", "seclists_termux"),
                  "windows": ("special", "seclists_windows")},
         sudo=True, description="Standard wordlist collection"),
]


ALL_TOOLS = BASE_TOOLS + SECURITY_TOOLS + GO_TOOLS + RESOURCE_TOOLS
TOOLS_BY_NAME = {t.name: t for t in ALL_TOOLS}


def install_method_for(tool: Tool, p: PlatformInfo = PLATFORM) -> Optional[tuple[str, str]]:
    if "*" in tool.methods:
        return tool.methods["*"]
    key = p.kind
    if key == PlatformKind.NETHUNTER and "nethunter" not in tool.methods:
        key = PlatformKind.TERMUX
    return tool.methods.get(key)


# ══════════════════════════════════════════════════════════════════════════
#  ᚾ  VERIFICATION
# ══════════════════════════════════════════════════════════════════════════

def is_installed(tool: Tool) -> bool:
    """
    Verify a tool is installed. Order:
      1. Binary on PATH (authoritative)
      2. Binary in go/cargo bin dir
      3. Directory-based check_cmd (seclists)
      4. Fall back to check_cmd exit code
    """
    ensure_paths()

    if tool.resolved_binary and cmd_available(tool.resolved_binary):
        if tool.check_cmd and not run_check(tool.check_cmd):
            log.debug(f"{tool.name}: binary present, check_cmd returned non-zero — accepting")
        return True

    for candidate_dir in (go_bin_dir(), cargo_bin_dir()):
        try:
            if (candidate_dir / tool.resolved_binary).exists():
                return True
        except (OSError, AttributeError):
            pass

    if tool.check_cmd and not tool.resolved_binary:
        return run_check(tool.check_cmd)

    if tool.check_cmd:
        return run_check(tool.check_cmd)

    return False


def _auto_diagnose(tool: Tool) -> None:
    """Deep diagnostic when verification fails."""
    log.warn(f"  ── diagnostic for {tool.name} ──")
    log.info(f"  binary name    : {tool.resolved_binary}")
    log.info(f"  check_cmd      : {tool.check_cmd or '(none)'}")

    which = shutil.which(tool.resolved_binary)
    log.info(f"  which(binary)  : {which or 'NOT FOUND on PATH'}")

    if cmd_available("go"):
        gb = go_bin_dir()
        gb_bin = gb / tool.resolved_binary
        log.info(f"  go bin dir     : {gb}")
        log.info(f"  go bin binary  : {'EXISTS' if gb_bin.exists() else 'missing'}")
        ok, gobin, _ = run(["go", "env", "GOBIN"], quiet=True)
        if ok:
            log.info(f"  go env GOBIN   : {gobin.strip() or '(empty, using GOPATH/bin)'}")
        ok, gopath, _ = run(["go", "env", "GOPATH"], quiet=True)
        if ok:
            log.info(f"  go env GOPATH  : {gopath.strip() or '(empty, using default ~/go)'}")
    else:
        log.info(f"  go compiler    : NOT AVAILABLE")

    cb = cargo_bin_dir()
    cb_bin = cb / tool.resolved_binary
    log.info(f"  cargo bin dir  : {cb}")
    log.info(f"  cargo bin bin  : {'EXISTS' if cb_bin.exists() else 'missing'}")
    log.info(f"  CARGO_HOME env : {os.environ.get('CARGO_HOME', '(not set)')}")

    if tool.check_cmd:
        if any(c in tool.check_cmd for c in "|&;()<>"):
            cmd = ["/bin/sh", "-c", tool.check_cmd]
        else:
            try:
                cmd = shlex.split(tool.check_cmd)
            except ValueError:
                cmd = []
        if cmd:
            ok, out, err = run(cmd, quiet=True, timeout=10)
            log.info(f"  check_cmd exit : {'0' if ok else 'non-zero'}")
            if out.strip():
                log.info(f"  check_cmd out  : {out.strip()[:150]}")
            if err.strip():
                log.info(f"  check_cmd err  : {err.strip()[:150]}")

    log.info(f"  PATH           : {os.environ.get('PATH', '')[:200]}")
    log.warn(f"  ── end diagnostic ──")


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  INSTALLERS (per method)
# ══════════════════════════════════════════════════════════════════════════

def install_via_pkg(tool: Tool, pkg_name: str) -> bool:
    if not PKG:
        log.warn("  no package manager available")
        return False
    cmd = PKG.install_cmd + [pkg_name]
    ok, _, err = run(cmd, sudo=PKG.needs_sudo, timeout=900, quiet=True)
    if not ok:
        log.warn(f"  {PKG.name} install {pkg_name} failed: {err.strip()[:250]}")
    return ok


def install_via_go(tool: Tool, module: str) -> bool:
    ensure_paths()
    if not cmd_available("go"):
        log.error(f"  go compiler missing — cannot install {tool.name}")
        return False
    if LIGHTWEIGHT_MODE and not _confirm_heavy_compile(tool.name):
        return False
    log.info(f"  go install {module}")
    ok, _, err = run(["go", "install", module], timeout=1200, quiet=True)
    if not ok:
        log.warn(f"  go install failed: {err.strip()[:250]}")
        return False
    ensure_paths()
    return (go_bin_dir() / tool.resolved_binary).exists() or cmd_available(tool.resolved_binary)


def install_via_cargo(tool: Tool, crate: str) -> bool:
    ensure_paths()
    if not cmd_available("cargo"):
        log.warn(f"  cargo missing — attempting to install rust")
        if not _install_rust():
            return False
        ensure_paths()
    if LIGHTWEIGHT_MODE and not _confirm_heavy_compile(tool.name):
        return False
    log.info(f"  cargo install {crate} (compiling, may take minutes)")
    ok, _, err = run(["cargo", "install", crate], timeout=1800, quiet=True)
    if not ok:
        log.warn(f"  cargo install failed: {err.strip()[:250]}")
        return False
    ensure_paths()
    return (cargo_bin_dir() / tool.resolved_binary).exists() or cmd_available(tool.resolved_binary)


def install_via_brew(tool: Tool, formula: str) -> bool:
    if not cmd_available("brew"):
        return False
    ok, _, err = run(["brew", "install", formula], timeout=1200, quiet=True)
    if not ok:
        log.warn(f"  brew install {formula} failed: {err.strip()[:250]}")
    return ok


def install_via_winget(tool: Tool, package_id: str) -> bool:
    if not cmd_available("winget"):
        return False
    cmd = ["winget", "install", "--id", package_id, "--exact", "--silent",
           "--accept-package-agreements", "--accept-source-agreements"]
    ok, _, err = run(cmd, timeout=1200, quiet=True)
    if not ok:
        log.warn(f"  winget install {package_id} failed: {err.strip()[:250]}")
    return ok


def install_via_scoop(tool: Tool, package: str) -> bool:
    if not cmd_available("scoop"):
        return False
    ok, _, err = run(["scoop", "install", package], timeout=900, quiet=True)
    if not ok:
        log.warn(f"  scoop install {package} failed: {err.strip()[:250]}")
    return ok


def install_via_choco(tool: Tool, package: str) -> bool:
    if not cmd_available("choco"):
        return False
    ok, _, err = run(["choco", "install", package, "-y"], sudo=True,
                     timeout=900, quiet=True)
    if not ok:
        log.warn(f"  choco install {package} failed: {err.strip()[:250]}")
    return ok


def install_via_git(tool: Tool, repo_url: str) -> bool:
    dest = Path("/opt") / tool.name if os.name != "nt" else Path.home() / "tools" / tool.name
    if dest.exists():
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    ok, _, err = run(["git", "clone", "--depth", "1", repo_url, str(dest)],
                     sudo=(os.name != "nt" and PLATFORM.has_sudo and not PLATFORM.is_root),
                     timeout=900, quiet=True)
    if not ok:
        log.warn(f"  git clone failed: {err.strip()[:250]}")
    return ok


# ══════════════════════════════════════════════════════════════════════════
#  ᛜ  SPECIAL HANDLERS
# ══════════════════════════════════════════════════════════════════════════

def handle_seclists_debian(tool: Tool) -> bool:
    ok, _, _ = run(["apt-get", "install", "-y", "-q", "seclists"],
                   sudo=True, timeout=600, quiet=True)
    if ok and Path("/usr/share/seclists").exists():
        return True
    return install_via_git(tool, "https://github.com/danielmiessler/SecLists.git")


def handle_seclists_brew(tool: Tool) -> bool:
    return install_via_brew(tool, "seclists")


def handle_seclists_termux(tool: Tool) -> bool:
    ok, _, _ = run(["pkg", "install", "-y", "seclists"], timeout=600, quiet=True)
    if ok:
        return True
    dest = Path.home() / "seclists"
    if dest.exists():
        return True
    ok, _, err = run(["git", "clone", "--depth", "1",
                      "https://github.com/danielmiessler/SecLists.git",
                      str(dest)], timeout=900, quiet=True)
    return ok


def handle_seclists_windows(tool: Tool) -> bool:
    dest = Path.home() / "SecLists"
    if dest.exists():
        return True
    ok, _, err = run(["git", "clone", "--depth", "1",
                      "https://github.com/danielmiessler/SecLists.git",
                      str(dest)], timeout=900, quiet=True)
    return ok

# ══════════════════════════════════════════════════════════════════════════
#  findomain  ·  GitHub release binary installer
# ══════════════════════════════════════════════════════════════════════════

_FINDOMAIN_BASE = "https://github.com/findomain/findomain/releases/latest/download"

def _findomain_url() -> Optional[tuple[str, str]]:
    """
    Return (url, binary_name_in_zip) for the current platform, or None
    if there is no pre-built binary available.
    """
    machine = PLATFORM.arch.lower()

    if PLATFORM.kind == PlatformKind.MACOS:
        return (f"{_FINDOMAIN_BASE}/findomain-macos.zip", "findomain")

    if PLATFORM.kind == PlatformKind.WINDOWS:
        return (f"{_FINDOMAIN_BASE}/findomain-win.zip", "findomain.exe")

    if PLATFORM.kind == PlatformKind.LINUX:
        if machine in ("x86_64", "amd64"):
            return (f"{_FINDOMAIN_BASE}/findomain-linux.zip", "findomain")
        if machine in ("aarch64", "arm64"):
            return (f"{_FINDOMAIN_BASE}/findomain-linux-arm64.zip", "findomain")
        if machine.startswith("arm"):
            return (f"{_FINDOMAIN_BASE}/findomain-linux-arm.zip", "findomain")
        if machine in ("i386", "i686"):
            return (f"{_FINDOMAIN_BASE}/findomain-linux-i386.zip", "findomain")

    return None


def handle_findomain(tool: Tool) -> bool:
    """
    Install findomain from the official GitHub release binary.

    Strategy:
      1. Download the platform-appropriate .zip
      2. Extract, find the binary
      3. Install to /usr/local/bin (sudo) → ~/.local/bin (user) → cargo (compile)
    """
    import zipfile

    spec = _findomain_url()
    if spec is None:
        log.warn(f"  no findomain binary for {PLATFORM.kind}/{PLATFORM.arch} — falling back to cargo")
        return _fallback_cargo_findomain(tool)

    url, binary_name = spec
    log.info(f"  downloading findomain binary ({PLATFORM.kind}/{PLATFORM.arch})...")

    with tempfile.TemporaryDirectory() as tmp:
        tmppath = Path(tmp)
        zip_path = tmppath / "findomain.zip"

        # 1. Download
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": f"argus-tools/{VERSION}",
            })
            with urllib.request.urlopen(req, timeout=120) as resp:
                zip_path.write_bytes(resp.read())
        except urllib.error.HTTPError as e:
            log.warn(f"  findomain download HTTP {e.code} — falling back to cargo")
            return _fallback_cargo_findomain(tool)
        except Exception as e:
            log.warn(f"  findomain download failed: {type(e).__name__}: {e}")
            return _fallback_cargo_findomain(tool)

        # 2. Extract
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(tmppath)
        except Exception as e:
            log.warn(f"  findomain extraction failed: {e}")
            return False

        # 3. Locate binary (may be nested in a folder inside the zip)
        candidates = list(tmppath.rglob(binary_name))
        # Exclude the downloaded zip itself
        candidates = [c for c in candidates if c.is_file() and c != zip_path]
        if not candidates:
            log.warn(f"  findomain binary '{binary_name}' not found in archive")
            return False
        source = candidates[0]
        log.debug(f"  extracted binary: {source} ({source.stat().st_size} bytes)")

        # 4. Install
        if PLATFORM.kind == PlatformKind.WINDOWS:
            target = Path.home() / "tools" / binary_name
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(source, target)
                _add_to_path_windows(str(target.parent))
                return True
            except Exception as e:
                log.warn(f"  findomain copy failed: {e}")
                return False

        # Unix: try /usr/local/bin first (with sudo), then ~/.local/bin
        installed = False
        for target_dir in (Path("/usr/local/bin"),
                           Path.home() / ".local" / "bin"):
            target = target_dir / "findomain"
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                pass

            # Try direct copy first (fast, no sudo if user owns the dir)
            try:
                shutil.copy2(source, target)
                target.chmod(0o755)
                installed = True
                log.debug(f"  installed to {target}")
                break
            except (PermissionError, OSError):
                pass

            # Try sudo copy
            if PLATFORM.has_sudo:
                ok, _, err = run(
                    ["install", "-m", "0755", str(source), str(target)],
                    sudo=True, quiet=True,
                )
                if ok:
                    installed = True
                    log.debug(f"  installed to {target} (via sudo)")
                    break
                else:
                    log.debug(f"  sudo install to {target} failed: {err[:200]}")

        if not installed:
            log.warn("  findomain install to /usr/local/bin and ~/.local/bin both failed")
            return False

        # Refresh PATH and verify
        ensure_paths()
        return cmd_available("findomain")


def _fallback_cargo_findomain(tool: Tool) -> bool:
    """Compile findomain from source via cargo. Slow but reliable."""
    if not cmd_available("cargo"):
        if not _install_rust():
            log.warn("  findomain fallback: no cargo available")
            return False
    if LIGHTWEIGHT_MODE and not _confirm_heavy_compile(tool.name):
        return False
    log.info("  cargo install findomain (compiling, may take 5-10 min)...")
    ok, _, err = run(["cargo", "install", "findomain"], timeout=1800, quiet=True)
    if not ok:
        log.warn(f"  cargo install findomain failed: {err.strip()[:250]}")
        return False
    ensure_paths()
    return cmd_available("findomain")


def _add_to_path_windows(directory: str) -> None:
    """Print the setx hint to persist a directory to PATH on Windows."""
    log.info(f"  add to PATH: {_c('dim')}setx PATH \"{directory};%PATH%\"{_c('reset')}")

SPECIAL_HANDLERS: dict[str, Callable[[Tool], bool]] = {
    "seclists_debian":  handle_seclists_debian,
    "seclists_brew":    handle_seclists_brew,
    "seclists_termux":  handle_seclists_termux,
    "seclists_windows": handle_seclists_windows,
    "findomain_binary": handle_findomain,         # ← NEW
}


# ══════════════════════════════════════════════════════════════════════════
#  ᛞ  RUST + HEAVY COMPILE GUARD
# ══════════════════════════════════════════════════════════════════════════

def _install_rust() -> bool:
    if cmd_available("cargo"):
        return True
    if LIGHTWEIGHT_MODE:
        log.warn("lightweight mode — skipping Rust install (compile-heavy)")
        return False
    if PLATFORM.kind == PlatformKind.WINDOWS:
        log.warn("install Rust manually from https://rustup.rs")
        return False
    if PLATFORM.kind in (PlatformKind.TERMUX, PlatformKind.NETHUNTER):
        ok, _, _ = run(["pkg", "install", "-y", "rust"], timeout=900, quiet=True)
        return ok
    if PLATFORM.kind == PlatformKind.MACOS:
        return install_via_brew(Tool("rust", "base"), "rust")
    if PKG:
        pkg = "rust" if PKG.name in ("apk", "pacman") else "cargo"
        ok, _, _ = run(PKG.install_cmd + [pkg], sudo=PKG.needs_sudo,
                       timeout=900, quiet=True)
        return ok
    return False


def _confirm_heavy_compile(tool_name: str) -> bool:
    log.warn(f"{tool_name} requires compiling from source.")
    log.warn(f"Host: {HOST.cpu_cores} cores / {HOST.ram_mb} MB RAM / {HOST.disk_free_mb} MB free")
    log.warn(f"Reason: {HOST.reason}")
    try:
        ans = input(f"  {_c('amber')}Continue? [y/N] {_c('reset')}").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


# ══════════════════════════════════════════════════════════════════════════
#  ᛃ  INSTALL DRIVER
# ══════════════════════════════════════════════════════════════════════════

def install_tool(tool: Tool, dry_run: bool = False, force: bool = False) -> str:
    if not force and is_installed(tool):
        return "present"

    method = install_method_for(tool)
    if not method:
        return "unsupported"

    kind, arg = method

    if dry_run:
        log.info(f"  {_c('dim')}{Sym.ARROW}{_c('reset')} {tool.name:<14} "
                 f"{_c('dim')}[dry-run: {kind} {arg}]{_c('reset')}")
        return "skipped"

    log.info(f"  {_c('cyan')}{Sym.ARROW}{_c('reset')} {tool.name:<14} installing via {kind}...")

    if kind == "pkg":
        ok = install_via_pkg(tool, arg)
    elif kind == "go":
        ok = install_via_go(tool, arg)
    elif kind == "cargo":
        ok = install_via_cargo(tool, arg)
    elif kind == "brew":
        ok = install_via_brew(tool, arg)
    elif kind == "winget":
        ok = install_via_winget(tool, arg)
    elif kind == "scoop":
        ok = install_via_scoop(tool, arg)
    elif kind == "choco":
        ok = install_via_choco(tool, arg)
    elif kind == "git":
        ok = install_via_git(tool, arg)
    elif kind == "special":
        handler = SPECIAL_HANDLERS.get(arg)
        ok = handler(tool) if handler else False
    else:
        ok = False

    if not ok:
        log.error(f"  {tool.name:<14} install FAILED")
        return "failed"

    for hook in tool.post_install:
        h_ok, _, h_err = run(shlex.split(hook), timeout=300, quiet=True)
        if not h_ok:
            log.warn(f"  {tool.name:<14} post-install hook failed: {hook}")

    ensure_paths()
    if not is_installed(tool):
        log.error(f"  {tool.name:<14} verification failed after install")
        _auto_diagnose(tool)
        return "failed"

    log.ok(f"  {tool.name:<14} installed")
    return "installed"


# ══════════════════════════════════════════════════════════════════════════
#  ᛖ  PRE-FLIGHT
# ══════════════════════════════════════════════════════════════════════════

def preflight() -> bool:
    log.rune(Rune.EHWAZ, "Pre-flight")
    log.info(f"OS           : {platform.system()} {platform.release()}")
    log.info(f"Distro       : {PLATFORM.distro_id or 'n/a'} (like: {PLATFORM.distro_like or 'n/a'})")
    log.info(f"Arch         : {PLATFORM.arch}")
    log.info(f"Root         : {PLATFORM.is_root}")
    log.info(f"Sudo         : {PLATFORM.has_sudo}")
    log.info(f"Package mgr  : {PKG.name if PKG else 'NONE DETECTED'}")
    log.info(f"Python       : {platform.python_version()}")
    log.info(f"Host         : {HOST.cpu_cores} cores / {HOST.ram_mb} MB RAM / {HOST.disk_free_mb} MB free")
    log.info(f"Lightweight  : {LIGHTWEIGHT_MODE} ({HOST.reason})")

    if not PKG and PLATFORM.kind not in (PlatformKind.TERMUX, PlatformKind.NETHUNTER):
        log.warn("no package manager detected — only go/cargo/git installs will work")
    return True


# ══════════════════════════════════════════════════════════════════════════
#  ᚨ  SELF-TEST  ·  verifies the script's own integrity
# ══════════════════════════════════════════════════════════════════════════

def selftest() -> int:
    """
    Verify every critical function exists and behaves sanely.
    This would have caught the missing `cmd_available` bug immediately.
    """
    print_banner()
    log.rune(Rune.ANSUZ, "Self-test · script integrity")

    tests: list[tuple[str, Callable[[], Any]]] = [
        ("platform detection",  lambda: PLATFORM.kind in (
            PlatformKind.LINUX, PlatformKind.MACOS, PlatformKind.WINDOWS,
            PlatformKind.TERMUX, PlatformKind.NETHUNTER)),
        ("package manager",     lambda: PKG is None or isinstance(PKG.name, str)),
        ("host measurement",    lambda: HOST.cpu_cores >= 1),
        ("tool registry",       lambda: len(ALL_TOOLS) > 0
                                        and len(TOOLS_BY_NAME) == len(ALL_TOOLS)),
        ("cmd_available",       lambda: callable(cmd_available)),
        ("run_check",           lambda: callable(run_check)),
        ("run",                 lambda: callable(run)),
        ("_sudo_available",     lambda: callable(_sudo_available)),
        ("ensure_sudo",         lambda: callable(ensure_sudo)),
        ("go_bin_dir",          lambda: isinstance(go_bin_dir(), Path)),
        ("cargo_bin_dir",       lambda: isinstance(cargo_bin_dir(), Path)),
        ("ensure_paths",        lambda: callable(ensure_paths)),
        ("is_installed",        lambda: callable(is_installed)),
        ("_auto_diagnose",      lambda: callable(_auto_diagnose)),
        ("install_via_pkg",     lambda: callable(install_via_pkg)),
        ("install_via_go",      lambda: callable(install_via_go)),
        ("install_via_cargo",   lambda: callable(install_via_cargo)),
        ("install_via_brew",    lambda: callable(install_via_brew)),
        ("install_via_winget",  lambda: callable(install_via_winget)),
        ("install_via_git",     lambda: callable(install_via_git)),
        ("install_method_for",  lambda: callable(install_method_for)),
        ("install_tool",        lambda: callable(install_tool)),
        ("_install_rust",       lambda: callable(_install_rust)),
        ("_confirm_heavy_compile", lambda: callable(_confirm_heavy_compile)),
        ("SPECIAL_HANDLERS",    lambda: all(callable(f) for f in SPECIAL_HANDLERS.values())),
        ("install_method resolution", lambda: all(
            install_method_for(t) is not None
            for t in ALL_TOOLS
            if any(k in t.methods for k in ("*", PLATFORM.kind))
        )),
        ("cmd_available(git)",  lambda: cmd_available("git") is True),
        ("run_check('true')",   lambda: run_check("true") is True),
    ]

    passed, failed = 0, 0
    for name, fn in tests:
        try:
            result = fn()
            if result is not False and result is not None:
                log.ok(name)
                passed += 1
            else:
                log.error(f"{name} → {result!r}")
                failed += 1
        except Exception as e:
            log.error(f"{name} → {type(e).__name__}: {e}")
            failed += 1

    print()
    if failed == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ SELFTEST PASSED · {passed} checks ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('crimson')}{Sym.SKULL}  ══ SELFTEST FAILED · {failed}/{passed+failed} ══  {Sym.SKULL}{_c('reset')}")
    return 1


# ══════════════════════════════════════════════════════════════════════════
#  ᛊ  MAIN
# ══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tools.py",
        description=f"Argus dependency smith v{VERSION} '{__codename__}'",
    )
    p.add_argument("--check", action="store_true", help="verify only; no installs")
    p.add_argument("--dry-run", action="store_true", help="show plan, change nothing")
    p.add_argument("--selftest", action="store_true", help="verify script integrity")
    p.add_argument("--lightweight", action="store_true", help="force lightweight mode")
    p.add_argument("--category", help="comma-separated: base,recon,scan,audit,util,resource")
    p.add_argument("--only", help="comma-separated tool names")
    p.add_argument("--skip", help="comma-separated tool names to skip")
    p.add_argument("--force", action="store_true", help="reinstall even if present")
    p.add_argument("--diagnose", metavar="TOOL", help="deep-dive a single tool")
    p.add_argument("--no-color", action="store_true", help="disable color")
    p.add_argument("--verbose", "-v", action="store_true", help="verbose")
    p.add_argument("--version", action="version", version=f"tools.py {VERSION}")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    global LIGHTWEIGHT_MODE
    args = build_parser().parse_args(argv)

    if args.no_color:
        Palette._enabled = False
    if args.lightweight:
        LIGHTWEIGHT_MODE = True
    if args.verbose:
        log.min_level = "debug"

    # ── Short-circuit modes ─────────────────────────────────────────────
    if args.selftest:
        return selftest()

    if args.diagnose:
        print_banner()
        tool = TOOLS_BY_NAME.get(args.diagnose)
        if not tool:
            log.error(f"unknown tool: {args.diagnose}")
            log.info(f"available: {', '.join(sorted(TOOLS_BY_NAME))}")
            return 2
        _auto_diagnose(tool)
        return 0 if is_installed(tool) else 1

    print_banner()
    preflight()

    # ── Selection ───────────────────────────────────────────────────────
    selected: list[Tool] = []
    if args.only:
        wanted = {x.strip() for x in args.only.split(",") if x.strip()}
        selected = [t for t in ALL_TOOLS if t.name in wanted]
        missing = wanted - {t.name for t in selected}
        if missing:
            log.warn(f"unknown tools: {', '.join(sorted(missing))}")
    elif args.category:
        cats = {x.strip() for x in args.category.split(",") if x.strip()}
        selected = [t for t in ALL_TOOLS if t.category in cats]
    else:
        selected = list(ALL_TOOLS)

    if args.skip:
        skips = {x.strip() for x in args.skip.split(",") if x.strip()}
        selected = [t for t in selected if t.name not in skips]

    if not selected:
        log.error("no tools selected")
        return 2

    # ── Sudo pre-cache (only if we'll actually need it) ─────────────────
    if not args.dry_run and not args.check:
        needs_sudo = any(
            (m := install_method_for(t)) is not None
            and m[0] in ("pkg", "winget", "choco", "special")
            and not is_installed(t)
            for t in selected
        )
        if needs_sudo:
            if not ensure_sudo():
                log.warn("continuing without cached sudo — installs may fail")

    # ── Check-only ──────────────────────────────────────────────────────
    if args.check:
        log.rune(Rune.SOWILO, "Verification")
        missing = 0
        for t in selected:
            if is_installed(t):
                log.ok(f"{t.name:<14} present")
            elif install_method_for(t) is None:
                log.info(f"{_c('grey')}{t.name:<14} unsupported on {PLATFORM.kind}{_c('reset')}")
            else:
                log.error(f"{t.name:<14} MISSING")
                missing += 1
        if missing:
            log.warn(f"{missing} tool(s) missing")
            return 1
        log.ok("all selected tools present")
        return 0

    # ── Refresh package index ───────────────────────────────────────────
    if PKG and PKG.update_cmd and not args.dry_run:
        log.rune(Rune.JERA, "Refresh package index")
        ok, _, err = run(PKG.update_cmd, sudo=PKG.needs_sudo, timeout=300, quiet=True)
        if ok:
            log.ok(f"{PKG.name} index refreshed")
        else:
            log.warn(f"{PKG.name} update failed (continuing)")
            log.debug(err)

    # ── Install ─────────────────────────────────────────────────────────
    log.rune(Rune.TIWAZ, "Forging tools")
    stats = {"present": 0, "installed": 0, "failed": 0, "skipped": 0, "unsupported": 0}

    for t in selected:
        result = install_tool(t, dry_run=args.dry_run, force=args.force)
        stats[result] = stats.get(result, 0) + 1

    # ── Summary ─────────────────────────────────────────────────────────
    log.rune(Rune.SOWILO, "Summary")
    log.ok(f"Present:     {stats['present']}")
    log.info(f"Installed:   {stats['installed']}")
    if stats["skipped"]:
        log.info(f"Skipped:     {stats['skipped']}")
    if stats["unsupported"]:
        log.info(f"Unsupported: {stats['unsupported']}")
    if stats["failed"]:
        log.error(f"Failed:      {stats['failed']}")

    if stats["installed"] and not args.dry_run:
        paths = []
        if cmd_available("go"):
            paths.append(str(go_bin_dir()))
        if cmd_available("cargo"):
            paths.append(str(cargo_bin_dir()))
        if paths:
            log.info("")
            log.warn("persist tool binaries to your PATH:")
            joined = os.pathsep.join(paths)
            if PLATFORM.kind == PlatformKind.WINDOWS:
                log.info(f"  {_c('dim')}setx PATH \"{joined};%PATH%\"{_c('reset')}")
            else:
                log.info(f"  {_c('dim')}echo 'export PATH=\"{joined}:$PATH\"' >> ~/.bashrc{_c('reset')}")
                log.info(f"  {_c('dim')}source ~/.bashrc{_c('reset')}")

    print()
    if stats["failed"] == 0:
        print(f"{_c('green')}{Sym.SHIELD}  ══ SMIDR FORGE COMPLETE ══  {Sym.SHIELD}{_c('reset')}")
        return 0
    print(f"{_c('crimson')}{Sym.SKULL}  ══ {stats['failed']} TOOL(S) FAILED TO FORGE ══  {Sym.SKULL}{_c('reset')}")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.warn("interrupted")
        sys.exit(130)
