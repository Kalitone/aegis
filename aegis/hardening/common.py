"""
AEGIS Hardening — Cross-Platform Core
======================================
Defines the Finding data model, HardeningRunner, and checks that apply to
every supported OS. Platform-specific checks live in linux.py / windows.py.

A Finding describes one hardening gap. Each finding has:
  - an identifier (stable across versions)
  - a severity
  - a human description
  - a callable `fix` (may be None for report-only checks)

The runner enumerates checks, returns findings, and can apply fixes that
have a `fix` callable. Everything is JSON-serialisable.
"""

import os
import json
import stat
import socket
import logging
import platform as _platform
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Callable

logger = logging.getLogger("aegis.hardening")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    check_id: str
    title: str
    description: str
    severity: Severity
    target: str = ""                 # file/path/key this finding applies to
    status: str = "open"             # open | fixed | skipped | error
    platform: str = ""
    fixable: bool = False
    fix_error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# A Check is a callable that returns list[Finding]. If any finding has
# fixable=True, the runner will look up the matching fix callable in FIXES.
Check = Callable[[], list[Finding]]
Fixer = Callable[[Finding], None]


# ── Cross-platform checks ──────────────────────────────────────────

def check_world_writable_in_path() -> list[Finding]:
    """Any directory in PATH that is world-writable is a privilege escalation risk."""
    findings = []
    # POSIX mode bits (S_IWOTH) have no useful meaning on Windows — Windows
    # uses ACLs. Skip cleanly rather than report ~30 false positives.
    if _platform.system().lower() == "windows":
        return findings
    path_env = os.environ.get("PATH", "")
    seen = set()
    for entry in path_env.split(os.pathsep):
        if not entry or entry in seen:
            continue
        seen.add(entry)
        try:
            st = os.stat(entry)
        except OSError:
            continue
        if hasattr(stat, "S_IWOTH") and st.st_mode & stat.S_IWOTH:
            findings.append(Finding(
                check_id="COMMON-001",
                title="World-writable directory in PATH",
                description=f"{entry} is world-writable and in PATH — any user can plant binaries.",
                severity=Severity.CRITICAL,
                target=entry,
                platform="common",
                fixable=True,
            ))
    return findings


def fix_world_writable_in_path(finding: Finding) -> None:
    """Strip the world-writable bit."""
    path = finding.target
    st = os.stat(path)
    os.chmod(path, st.st_mode & ~stat.S_IWOTH)


def check_ssh_config() -> list[Finding]:
    """Audit common weak SSH server settings."""
    findings = []
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return findings
    try:
        content = sshd_config.read_text(errors="ignore")
    except OSError:
        return findings

    rules = [
        ("PermitRootLogin yes", "COMMON-010", "SSH allows root login",
         "PermitRootLogin is set to yes. Root logins should be disabled.",
         Severity.HIGH),
        ("PasswordAuthentication yes", "COMMON-011", "SSH allows password auth",
         "Password authentication is enabled. Prefer key-based auth.",
         Severity.MEDIUM),
        ("PermitEmptyPasswords yes", "COMMON-012", "SSH allows empty passwords",
         "Empty passwords accepted — critical exposure.",
         Severity.CRITICAL),
    ]
    lowered = content.lower()
    for needle, cid, title, desc, sev in rules:
        if needle.lower() in lowered:
            findings.append(Finding(
                check_id=cid, title=title, description=desc, severity=sev,
                target=str(sshd_config), platform="common", fixable=False,
            ))
    return findings


def check_weak_sensitive_permissions() -> list[Finding]:
    """Files that must not be world-writable."""
    findings = []
    sensitive = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/sudoers", "/etc/ssh/sshd_config",
    ]
    for p in sensitive:
        path = Path(p)
        if not path.exists():
            continue
        try:
            st = path.stat()
        except OSError:
            continue
        if hasattr(stat, "S_IWOTH") and st.st_mode & stat.S_IWOTH:
            findings.append(Finding(
                check_id="COMMON-020",
                title=f"World-writable sensitive file: {p}",
                description=f"{p} is world-writable. Attackers can modify it.",
                severity=Severity.CRITICAL,
                target=p, platform="common", fixable=True,
            ))
    return findings


def fix_tighten_sensitive_permissions(finding: Finding) -> None:
    path = finding.target
    st = os.stat(path)
    os.chmod(path, st.st_mode & ~stat.S_IWOTH & ~stat.S_IWGRP)


COMMON_CHECKS: list[Check] = [
    check_world_writable_in_path,
    check_ssh_config,
    check_weak_sensitive_permissions,
]

COMMON_FIXES: dict[str, Fixer] = {
    "COMMON-001": fix_world_writable_in_path,
    "COMMON-020": fix_tighten_sensitive_permissions,
}


class HardeningRunner:
    """
    Runs hardening checks and (optionally) applies fixes.

    platform: "auto" (detect) | "linux" | "windows" | "common"
    """

    def __init__(self, platform: str = "auto"):
        if platform == "auto":
            platform = _platform.system().lower()
        self.platform = platform
        self._checks: list[Check] = list(COMMON_CHECKS)
        self._fixes: dict[str, Fixer] = dict(COMMON_FIXES)
        self._load_platform_checks()

    def _load_platform_checks(self):
        if self.platform == "linux":
            try:
                from . import linux as _linux
                self._checks.extend(_linux.CHECKS)
                self._fixes.update(_linux.FIXES)
            except Exception as e:
                logger.warning(f"Could not load linux checks: {e}")
        elif self.platform == "windows":
            try:
                from . import windows as _win
                self._checks.extend(_win.CHECKS)
                self._fixes.update(_win.FIXES)
            except Exception as e:
                logger.warning(f"Could not load windows checks: {e}")

    def audit(self) -> list[Finding]:
        """Run every check and return findings."""
        findings: list[Finding] = []
        for check in self._checks:
            try:
                result = check() or []
                findings.extend(result)
            except Exception as e:
                logger.error(f"Check {check.__name__} failed: {e}", exc_info=True)
                findings.append(Finding(
                    check_id=f"ERROR-{check.__name__}",
                    title=f"Check error: {check.__name__}",
                    description=str(e),
                    severity=Severity.LOW,
                    platform=self.platform,
                    status="error",
                ))
        logger.info(f"Hardening audit complete: {len(findings)} findings")
        return findings

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Apply fixes to every fixable finding. Returns the (mutated) findings."""
        for f in findings:
            if not f.fixable or f.status != "open":
                continue
            fixer = self._fixes.get(f.check_id)
            if not fixer:
                f.status = "skipped"
                continue
            try:
                fixer(f)
                f.status = "fixed"
                logger.info(f"Fixed: {f.check_id} {f.target}")
            except Exception as e:
                f.status = "error"
                f.fix_error = str(e)
                logger.error(f"Fix failed for {f.check_id}: {e}")
        return findings

    def report(self, findings: list[Finding]) -> str:
        """Render findings as JSON."""
        return json.dumps({
            "hostname": socket.gethostname(),
            "platform": self.platform,
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }, indent=2)
