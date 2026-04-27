"""
AEGIS — Software Bill of Materials (CycloneDX 1.5)
===================================================
Periodically emits a host-level SBOM listing every Python (pip) and
globally-installed npm package. Pairs with the existing supply-chain
scanner: SBOMs are the inventory; supply_chain.py is the rule engine
that grades the inventory against typosquats / known-malicious /
license rules.

Output
------
* `data/sbom.cdx.json` — CycloneDX 1.5 document, refreshed every
  `interval_hours` (default 24h) and once at startup.
* One `system.health` event published per emit so the dashboard /
  OCSF feed sees the cadence.

Why CycloneDX 1.5
-----------------
* Linux Foundation OWASP project, stable schema, JSON wire format.
* Splunk / Elastic / Sentinel / Dependency-Track ingest it directly.
* Compatible with Microsoft's SBOM Tool, Anchore Syft, CycloneDX-CLI.

Why npm but not pacman/dpkg/winget for v1
-----------------------------------------
pip and npm cover the supply-chain risk surface AEGIS already cares
about. Adding system-package collectors is a Phase 2 task — they're
3 OS-specific shellouts each and a thicker test matrix. The CycloneDX
schema is open-ended, so a future commit can fold them in without
breaking consumers.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.utils.sbom")


_SPEC_VERSION = "1.5"
_TOOL_VENDOR = "AEGIS"
_TOOL_NAME = "aegis-sbom"
_TOOL_VERSION = "0.2.0"


# ── Pip / npm collectors ────────────────────────────────────────────

def collect_python_packages() -> list[dict]:
    """Use `importlib.metadata` (stdlib) to list every installed
    distribution. Returns [{name, version, purl}, ...]."""
    out: list[dict] = []
    try:
        from importlib import metadata as md
    except ImportError:   # very old Python — should not happen on 3.10+
        return out
    seen: set[tuple[str, str]] = set()
    for dist in md.distributions():
        try:
            name = (dist.metadata.get("Name") or dist.name or "").strip()
            version = (dist.version or "").strip()
        except Exception:
            continue
        if not name:
            continue
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        })
    out.sort(key=lambda c: (c["name"].lower(), c["version"]))
    return out


def collect_npm_packages(*, timeout_seconds: float = 30.0) -> list[dict]:
    """Shell out to `npm list -g --depth=0 --json`. Silent if npm is
    not on PATH. Returns [{name, version, purl}, ...]."""
    npm_bin = "npm.cmd" if platform.system().lower() == "windows" else "npm"
    try:
        proc = subprocess.run(
            [npm_bin, "list", "-g", "--depth=0", "--json"],
            capture_output=True, text=True, timeout=timeout_seconds,
            errors="ignore",
        )
    except FileNotFoundError:
        return []
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug(f"npm collect failed: {e}")
        return []
    if not proc.stdout:
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    deps = payload.get("dependencies") or {}
    out: list[dict] = []
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = (info.get("version") or "").strip()
        if not name:
            continue
        out.append({
            "name": name,
            "version": version,
            "purl": f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}",
        })
    out.sort(key=lambda c: (c["name"].lower(), c["version"]))
    return out


# ── CycloneDX assembly ──────────────────────────────────────────────

def build_cyclonedx(
    *,
    python_pkgs: Optional[list[dict]] = None,
    npm_pkgs: Optional[list[dict]] = None,
    hostname: Optional[str] = None,
    timestamp: Optional[float] = None,
    serial_number: Optional[str] = None,
) -> dict:
    """Assemble a CycloneDX 1.5 JSON document. Keyword args are
    overridable so tests don't have to monkey-patch socket / time /
    uuid to get a deterministic doc."""
    if python_pkgs is None:
        python_pkgs = collect_python_packages()
    if npm_pkgs is None:
        npm_pkgs = collect_npm_packages()
    if hostname is None:
        hostname = socket.gethostname()
    ts = datetime.fromtimestamp(
        timestamp if timestamp is not None else time.time(), tz=timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    serial = serial_number or f"urn:uuid:{uuid.uuid4()}"

    components: list[dict] = []
    for c in python_pkgs:
        components.append({
            "type": "library",
            "bom-ref": c["purl"],
            "name": c["name"],
            "version": c["version"],
            "purl": c["purl"],
            "scope": "required",
            "properties": [{"name": "aegis:source", "value": "pip"}],
        })
    for c in npm_pkgs:
        components.append({
            "type": "library",
            "bom-ref": c["purl"],
            "name": c["name"],
            "version": c["version"],
            "purl": c["purl"],
            "scope": "required",
            "properties": [{"name": "aegis:source", "value": "npm"}],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [{
                "vendor": _TOOL_VENDOR,
                "name": _TOOL_NAME,
                "version": _TOOL_VERSION,
            }],
            "component": {
                "type": "application",
                "bom-ref": f"aegis-host:{hostname}",
                "name": "aegis-host",
                "version": hostname,
                "properties": [
                    {"name": "aegis:platform", "value": platform.system()},
                    {"name": "aegis:python", "value": platform.python_version()},
                ],
            },
        },
        "components": components,
    }


# ── File output ────────────────────────────────────────────────────

def write_sbom(out_path: str | os.PathLike,
               *, include_npm: bool = True) -> dict:
    """Collect + assemble + write the SBOM. Returns a small summary
    dict {path, components, python, npm, serial} for logging /
    publishing."""
    python_pkgs = collect_python_packages()
    npm_pkgs = collect_npm_packages() if include_npm else []
    doc = build_cyclonedx(python_pkgs=python_pkgs, npm_pkgs=npm_pkgs)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.replace(tmp, out)

    return {
        "path": str(out),
        "components": len(doc["components"]),
        "python": len(python_pkgs),
        "npm": len(npm_pkgs),
        "serial": doc["serialNumber"],
        "spec_version": doc["specVersion"],
    }


# ── Periodic emitter (background thread) ───────────────────────────

class SbomEmitter:
    """Writes the SBOM at startup and every `interval_hours` after.

    Synchronous on the worker thread on purpose: the emit is fast
    (~tens of ms for ~150 pip packages) and putting it behind a queue
    obscures errors. Failures log at WARNING and the thread keeps
    running — a missed emit is not worth crashing AEGIS over.
    """

    def __init__(self, event_bus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", False))
        self.path = Path(self.config.get("path", "data/sbom.cdx.json"))
        self.interval_hours = float(self.config.get("interval_hours", 24))
        self.include_npm = bool(self.config.get("include_npm", True))
        self.emit_on_start = bool(self.config.get("emit_on_start", True))
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if not self.enabled:
            logger.info("SbomEmitter: disabled in config")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="aegis-sbom",
        )
        self._thread.start()
        logger.info(
            f"SbomEmitter started (interval={self.interval_hours}h, "
            f"include_npm={self.include_npm})"
        )

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def emit_once(self) -> dict:
        """Public hook so tests + the operator CLI can force an emit
        without waiting for the schedule."""
        return self._emit_and_publish()

    def _loop(self):
        if self.emit_on_start:
            try:
                self._emit_and_publish()
            except Exception as e:
                logger.warning(f"SbomEmitter startup emit failed: {e}")
        period_s = self.interval_hours * 3600
        slept = 0.0
        while self._running:
            time.sleep(1.0)
            slept += 1.0
            if slept < period_s:
                continue
            slept = 0.0
            try:
                self._emit_and_publish()
            except Exception as e:
                logger.warning(f"SbomEmitter scheduled emit failed: {e}")

    def _emit_and_publish(self) -> dict:
        summary = write_sbom(self.path, include_npm=self.include_npm)
        logger.info(
            f"SBOM emitted: {summary['components']} components "
            f"({summary['python']} pip, {summary['npm']} npm) → "
            f"{summary['path']}"
        )
        # Publish a small event so the dashboard / OCSF feed gets the
        # cadence. Lazy-import EventCategory to keep this module
        # safe to import in standalone CLI paths.
        try:
            from aegis.core import Event, EventCategory, Severity
            self.bus.publish(Event(
                category=EventCategory.SYSTEM_HEALTH,
                severity=Severity.INFO,
                source="sbom",
                data={"action": "sbom_emitted", **summary},
            ))
        except Exception as e:
            logger.debug(f"SBOM event publish failed: {e}")
        return summary


__all__ = [
    "collect_python_packages",
    "collect_npm_packages",
    "build_cyclonedx",
    "write_sbom",
    "SbomEmitter",
]
