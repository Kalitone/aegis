"""
AEGIS Hardening — Windows
===========================
Windows-specific hardening checks. Most checks are advisory (no auto-fix) —
changing Windows security settings is high-risk and policy-dependent.
"""

import os
import logging
import subprocess
from pathlib import Path

from .common import Finding, Severity, Check, Fixer

logger = logging.getLogger("aegis.hardening.windows")


UNNECESSARY_SERVICES = [
    "RemoteRegistry",       # Remote registry access
    "Fax",
    "Telnet",
    "TlntSvr",
    "SNMPTRAP",
    "SSDPSRV",              # SSDP discovery
    "upnphost",             # UPnP host
]


def _run_ps(command: str, timeout: int = 15) -> tuple[int, str]:
    """Run a PowerShell one-liner. Returns (rc, stdout)."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, (proc.stdout or "")
    except (subprocess.SubprocessError, OSError, FileNotFoundError) as e:
        logger.debug(f"PowerShell invocation failed: {e}")
        return -1, ""


def check_unnecessary_services() -> list[Finding]:
    findings = []
    for svc in UNNECESSARY_SERVICES:
        rc, out = _run_ps(
            f"(Get-Service -Name '{svc}' -ErrorAction SilentlyContinue).Status"
        )
        if rc != 0:
            continue
        status = out.strip()
        if status and status.lower() == "running":
            findings.append(Finding(
                check_id="WIN-001",
                title=f"Unnecessary service running: {svc}",
                description=(f"Service '{svc}' is running and is frequently "
                             f"abused for persistence or lateral movement."),
                severity=Severity.MEDIUM,
                target=svc, platform="windows",
                fixable=True,
            ))
    return findings


def fix_disable_service(finding: Finding) -> None:
    svc = finding.target
    rc, _ = _run_ps(
        f"Stop-Service -Name '{svc}' -Force -ErrorAction Stop; "
        f"Set-Service -Name '{svc}' -StartupType Disabled"
    )
    if rc != 0:
        raise RuntimeError(f"Failed to disable service {svc}")


def check_local_admins() -> list[Finding]:
    """Enumerate local Administrators — report if more than 1 besides builtin."""
    rc, out = _run_ps(
        "Get-LocalGroupMember -Group 'Administrators' | "
        "Select-Object -ExpandProperty Name"
    )
    if rc != 0:
        return []
    members = [line.strip() for line in out.splitlines() if line.strip()]
    if len(members) > 3:  # allow some slack for default accounts
        return [Finding(
            check_id="WIN-002",
            title="Many local administrators",
            description=(f"{len(members)} accounts in local Administrators "
                         f"group: {', '.join(members[:10])}. Review and remove "
                         f"unnecessary accounts."),
            severity=Severity.MEDIUM,
            target="Administrators", platform="windows",
            fixable=False,
        )]
    return []


def check_firewall_enabled() -> list[Finding]:
    findings = []
    rc, out = _run_ps(
        "Get-NetFirewallProfile | "
        "Select-Object Name,Enabled | Format-Table -HideTableHeaders"
    )
    if rc != 0:
        return findings
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, enabled = parts[0], parts[1]
        if enabled.lower() == "false":
            findings.append(Finding(
                check_id="WIN-003",
                title=f"Firewall profile disabled: {name}",
                description=f"Windows Firewall profile '{name}' is disabled.",
                severity=Severity.HIGH,
                target=name, platform="windows",
                fixable=True,
            ))
    return findings


def fix_enable_firewall(finding: Finding) -> None:
    rc, _ = _run_ps(
        f"Set-NetFirewallProfile -Profile {finding.target} -Enabled True"
    )
    if rc != 0:
        raise RuntimeError("Failed to enable firewall profile")


def check_audit_policy() -> list[Finding]:
    """Process creation auditing should be enabled for good forensics."""
    rc, out = _run_ps(
        "auditpol /get /subcategory:'Process Creation'"
    )
    if rc != 0:
        return []
    if "Success" not in out and "Enable" not in out:
        return [Finding(
            check_id="WIN-004",
            title="Process creation auditing disabled",
            description=("Process Creation audit policy is not set to Success. "
                         "Without it, Event ID 4688 will not fire."),
            severity=Severity.MEDIUM,
            target="Process Creation", platform="windows",
            fixable=True,
        )]
    return []


def fix_enable_process_audit(finding: Finding) -> None:
    rc, _ = _run_ps(
        "auditpol /set /subcategory:'Process Creation' "
        "/success:enable /failure:enable"
    )
    if rc != 0:
        raise RuntimeError("Failed to enable process creation auditing")


def check_defender_realtime() -> list[Finding]:
    rc, out = _run_ps(
        "(Get-MpPreference).DisableRealtimeMonitoring"
    )
    if rc != 0:
        return []
    if out.strip().lower() == "true":
        return [Finding(
            check_id="WIN-005",
            title="Defender real-time protection disabled",
            description=("Microsoft Defender real-time monitoring is disabled. "
                         "This is a critical gap."),
            severity=Severity.CRITICAL,
            target="DisableRealtimeMonitoring", platform="windows",
            fixable=True,
        )]
    return []


def fix_enable_defender(finding: Finding) -> None:
    rc, _ = _run_ps("Set-MpPreference -DisableRealtimeMonitoring $false")
    if rc != 0:
        raise RuntimeError("Failed to re-enable Defender real-time monitoring")


CHECKS: list[Check] = [
    check_unnecessary_services,
    check_local_admins,
    check_firewall_enabled,
    check_audit_policy,
    check_defender_realtime,
]

FIXES: dict[str, Fixer] = {
    "WIN-001": fix_disable_service,
    "WIN-003": fix_enable_firewall,
    "WIN-004": fix_enable_process_audit,
    "WIN-005": fix_enable_defender,
}
