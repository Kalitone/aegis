"""
AEGIS Hardening — Linux
=========================
Linux-specific hardening checks and fixes.
Every fix is idempotent. Checks never raise — they degrade to empty findings.
"""

import os
import stat
import shutil
import logging
import subprocess
from pathlib import Path

from .common import Finding, Severity, Check, Fixer

logger = logging.getLogger("aegis.hardening.linux")


# Binaries that commonly have SUID set but are rarely needed.
# Stripping SUID here does NOT break normal user operation for most systems.
NONESSENTIAL_SUID = [
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/newgrp",
    "/usr/bin/wall",
    "/usr/bin/write",
]

# Core GTFOBins-style SUID binaries that are explicitly dangerous if SUID.
DANGEROUS_SUID = [
    "/usr/bin/find", "/usr/bin/vim", "/usr/bin/nano", "/usr/bin/less",
    "/usr/bin/more", "/usr/bin/awk", "/usr/bin/python", "/usr/bin/python3",
    "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/nmap", "/usr/bin/tar",
    "/usr/bin/zip",
]

IMMUTABLE_TARGETS = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
]

# sysctl params we want set for hardening. Value is the desired string.
SYSCTL_HARDENING = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2",
    "kernel.yama.ptrace_scope": "2",
    "fs.protected_symlinks": "1",
    "fs.protected_hardlinks": "1",
    "fs.suid_dumpable": "0",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
}


# ── Checks ─────────────────────────────────────────────────────────

def check_suid_binaries() -> list[Finding]:
    findings = []
    for target in NONESSENTIAL_SUID + DANGEROUS_SUID:
        p = Path(target)
        if not p.exists():
            continue
        try:
            mode = p.stat().st_mode
        except OSError:
            continue
        if mode & stat.S_ISUID:
            severity = (Severity.CRITICAL if target in DANGEROUS_SUID
                        else Severity.MEDIUM)
            findings.append(Finding(
                check_id="LINUX-001",
                title=f"SUID set on {target}",
                description=(f"{target} has the SUID bit set. "
                             f"Remove it if not explicitly required."),
                severity=severity,
                target=target,
                platform="linux",
                fixable=True,
            ))
    return findings


def fix_strip_suid(finding: Finding) -> None:
    p = finding.target
    st = os.stat(p)
    os.chmod(p, st.st_mode & ~stat.S_ISUID)


def check_immutable_flags() -> list[Finding]:
    """Report if immutable (chattr +i) is NOT set on critical files."""
    findings = []
    if shutil.which("lsattr") is None:
        return findings
    for target in IMMUTABLE_TARGETS:
        if not Path(target).exists():
            continue
        try:
            out = subprocess.run(
                ["lsattr", "-d", target],
                capture_output=True, text=True, timeout=5,
            )
        except (subprocess.SubprocessError, OSError):
            continue
        line = (out.stdout or "").strip()
        # lsattr output format: "----i---------e---- /etc/passwd"
        attrs = line.split()[0] if line else ""
        if "i" not in attrs:
            findings.append(Finding(
                check_id="LINUX-002",
                title=f"No immutable flag on {target}",
                description=(f"{target} is not immutable (chattr +i). "
                             f"Set it to block unauthorised modification."),
                severity=Severity.MEDIUM,
                target=target, platform="linux",
                fixable=True,
            ))
    return findings


def fix_set_immutable(finding: Finding) -> None:
    if shutil.which("chattr") is None:
        raise RuntimeError("chattr not available")
    subprocess.run(["chattr", "+i", finding.target],
                   check=True, capture_output=True, timeout=5)


def check_cron_access() -> list[Finding]:
    """cron.allow should exist and restrict cron usage."""
    findings = []
    cron_allow = Path("/etc/cron.allow")
    cron_deny = Path("/etc/cron.deny")

    if not cron_allow.exists() and not cron_deny.exists():
        findings.append(Finding(
            check_id="LINUX-003",
            title="Unrestricted cron access",
            description=("Neither /etc/cron.allow nor /etc/cron.deny exists. "
                         "Any user can schedule cron jobs."),
            severity=Severity.MEDIUM,
            target="/etc/cron.allow", platform="linux",
            fixable=True,
        ))
    return findings


def fix_create_cron_allow(finding: Finding) -> None:
    path = Path(finding.target)
    path.write_text("root\n")
    os.chmod(path, 0o640)


def check_sysctl() -> list[Finding]:
    findings = []
    for key, desired in SYSCTL_HARDENING.items():
        current = _read_sysctl(key)
        if current is None:
            continue
        if current.strip() != desired:
            findings.append(Finding(
                check_id=f"LINUX-004:{key}",
                title=f"sysctl {key} not hardened",
                description=(f"{key}={current} (desired: {desired})"),
                severity=Severity.LOW,
                target=key, platform="linux",
                fixable=True,
            ))
    return findings


def _read_sysctl(key: str) -> str | None:
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return path.read_text().strip()
    except OSError:
        return None


def fix_sysctl(finding: Finding) -> None:
    key = finding.target
    desired = SYSCTL_HARDENING.get(key)
    if not desired:
        raise RuntimeError(f"No desired value known for sysctl {key}")
    path = Path("/proc/sys") / key.replace(".", "/")
    path.write_text(desired)


def check_core_dumps() -> list[Finding]:
    """Core dumps can leak secrets — should be disabled system-wide."""
    findings = []
    limits = Path("/etc/security/limits.conf")
    if not limits.exists():
        return findings
    try:
        content = limits.read_text(errors="ignore")
    except OSError:
        return findings
    if "hard core 0" not in content and "* hard core 0" not in content:
        findings.append(Finding(
            check_id="LINUX-005",
            title="Core dumps not disabled",
            description=("/etc/security/limits.conf does not hard-cap core "
                         "dumps to 0. Core dumps can leak memory contents."),
            severity=Severity.LOW,
            target=str(limits), platform="linux",
            fixable=False,
        ))
    return findings


def check_installed_package_count() -> list[Finding]:
    """Informational: number of installed packages (larger = larger attack surface)."""
    count = _package_count()
    if count == 0:
        return []
    return [Finding(
        check_id="LINUX-006",
        title="Installed package inventory",
        description=f"{count} packages installed. Review for unnecessary software.",
        severity=Severity.INFO,
        target=str(count), platform="linux", fixable=False,
    )]


def _package_count() -> int:
    for cmd in [["dpkg", "-l"], ["rpm", "-qa"]]:
        if shutil.which(cmd[0]) is None:
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                return sum(1 for _ in out.stdout.splitlines())
        except (subprocess.SubprocessError, OSError):
            pass
    return 0


CHECKS: list[Check] = [
    check_suid_binaries,
    check_immutable_flags,
    check_cron_access,
    check_sysctl,
    check_core_dumps,
    check_installed_package_count,
]

# LINUX-004 uses dynamic IDs (LINUX-004:<key>), handle via prefix matching in runner.
FIXES: dict[str, Fixer] = {
    "LINUX-001": fix_strip_suid,
    "LINUX-002": fix_set_immutable,
    "LINUX-003": fix_create_cron_allow,
}


# Register sysctl fixes dynamically for every known key
for _k in SYSCTL_HARDENING:
    FIXES[f"LINUX-004:{_k}"] = fix_sysctl
