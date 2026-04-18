"""
AEGIS Hardening Module
========================
Pre-deployment system hardening to reduce attack surface.

Usage:
    from aegis.hardening import HardeningRunner
    runner = HardeningRunner(platform="auto")
    findings = runner.audit()      # report only
    runner.apply(findings)         # apply fixes
"""

import platform as _platform

from .common import HardeningRunner, Finding, Severity as HardeningSeverity

__all__ = ["HardeningRunner", "Finding", "HardeningSeverity"]
