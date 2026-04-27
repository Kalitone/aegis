"""
AEGIS — OCSF (Open Cybersecurity Schema Framework) export
=========================================================
Pure-data mapper from an AEGIS `Event` to the OCSF v1.1.0 wire shape.
No I/O, no logging, no globals — every output is a function of its
input so the mapping is unit-testable without a bus or filesystem.

Why
---
OCSF is the Linux Foundation cybersecurity schema adopted by
Splunk, Elastic, AWS Security Lake, IBM QRadar, Microsoft Sentinel
and others. Emitting AEGIS events in OCSF lets the hash-chained log
be ingested as a credible audit artifact by any of those platforms
with zero per-vendor mapping work — and makes downstream forwarding
(syslog/CEF, S3 to Security Lake, Kafka to a SIEM) a one-liner.

Mapping strategy
----------------
* Headers (category/class/activity/severity/time/product) translate
  cleanly. AEGIS's `data` payload survives intact under OCSF's
  `unmapped` extension dict — preserve information first, polish
  vendor mappings later.
* Categories without a clean OCSF home (resource.*, system.health)
  fall back to (category=1 System Activity, class=1004 Module
  Activity, activity_id=0 Unknown). Better an honest "unknown" in
  the right category than an off-target class.
* `type_uid` is mechanically `class_uid * 100 + activity_id` per the
  OCSF spec; we compute it rather than table-driving it.

Schema reference
----------------
OCSF v1.1.0 — https://schema.ocsf.io/1.1.0
Category UIDs: 1 System Activity, 2 Findings, 3 IAM,
               4 Network Activity, 5 Discovery, 6 Application Activity
"""

from __future__ import annotations

from typing import Optional

from aegis.core import Event


_DEFAULT_SCHEMA_VERSION = "1.1.0"
_DEFAULT_PRODUCT_NAME = "AEGIS"
_DEFAULT_PRODUCT_VENDOR = "AEGIS"
_DEFAULT_PRODUCT_VERSION = "0.2.0"


# AEGIS category value -> (category_uid, class_uid, activity_id).
# `activity_id == 0` is OCSF "Unknown" — used when the source event has
# no obvious mapping verb (e.g. a generic system.health snapshot).
_EVENT_MAP: dict[str, tuple[int, int, int]] = {
    # ── System Activity (category 1) ────────────────────────────
    "file.create":    (1, 1001, 1),    # Create
    "file.modify":    (1, 1001, 3),    # Update
    "file.delete":    (1, 1001, 4),    # Delete
    "file.move":      (1, 1001, 6),    # Rename
    "proc.create":    (1, 1007, 1),    # Launch
    "proc.exit":      (1, 1007, 2),    # Terminate
    "proc.suspicious": (2, 2004, 1),   # Detection Finding > Create
    "resource.cpu":    (1, 1004, 0),
    "resource.memory": (1, 1004, 0),
    "resource.disk":   (1, 1004, 0),

    # ── Network Activity (category 4) ───────────────────────────
    "net.connect": (4, 4001, 1),       # Open
    "net.listen":  (4, 4001, 1),       # Open (inbound)
    "net.close":   (4, 4001, 2),       # Close

    # ── Findings (category 2) ───────────────────────────────────
    "detection.yara":         (2, 2004, 1),
    "detection.behavioral":   (2, 2004, 1),
    "detection.anomaly":      (2, 2004, 1),
    "detection.supply_chain": (2, 2004, 1),
    "detection.honeytoken":   (2, 2004, 1),
    "detection.amsi":         (2, 2004, 1),

    # ── Response (category 1 for actions, 2 for findings) ───────
    "response.kill":            (1, 1007, 2),  # Process Terminate
    "response.quarantine":      (2, 2004, 1),
    "response.alert":           (2, 2004, 1),
    "response.forensic":        (2, 2004, 1),
    "response.persistence":     (2, 2004, 1),
    "response.purge":           (2, 2004, 1),
    "response.hardening_drift": (2, 2003, 1),  # Compliance Finding

    # ── System lifecycle (category 1) ───────────────────────────
    "system.start":  (1, 1004, 1),
    "system.stop":   (1, 1004, 2),
    "system.error":  (1, 1004, 0),
    "system.health": (1, 1004, 0),
}

# Catch-all for any new AEGIS category that lands before this map is
# updated — keeps the export from blowing up on a `KeyError`.
_DEFAULT_TRIPLE: tuple[int, int, int] = (1, 1004, 0)


_CATEGORY_NAMES: dict[int, str] = {
    1: "System Activity",
    2: "Findings",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
}


_CLASS_NAMES: dict[int, str] = {
    1001: "File System Activity",
    1004: "Module Activity",
    1007: "Process Activity",
    2003: "Compliance Finding",
    2004: "Detection Finding",
    4001: "Network Activity",
}


# (class_uid, activity_id) -> human label per OCSF schema.
_ACTIVITY_NAMES: dict[tuple[int, int], str] = {
    (1001, 0): "Unknown",
    (1001, 1): "Create",
    (1001, 3): "Update",
    (1001, 4): "Delete",
    (1001, 6): "Rename",
    (1004, 0): "Unknown",
    (1004, 1): "Load",
    (1004, 2): "Unload",
    (1007, 0): "Unknown",
    (1007, 1): "Launch",
    (1007, 2): "Terminate",
    (2003, 0): "Unknown",
    (2003, 1): "Create",
    (2004, 0): "Unknown",
    (2004, 1): "Create",
    (4001, 0): "Unknown",
    (4001, 1): "Open",
    (4001, 2): "Close",
}


# AEGIS Severity.value -> OCSF severity_id + name. OCSF defines
# 0 Unknown / 1 Informational / 2 Low / 3 Medium / 4 High /
# 5 Critical / 6 Fatal — we never emit Fatal because AEGIS doesn't
# have a hard-stop severity above CRITICAL.
_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "info":     (1, "Informational"),
    "low":      (2, "Low"),
    "medium":   (3, "Medium"),
    "high":     (4, "High"),
    "critical": (5, "Critical"),
}


def _category_value(event: Event) -> str:
    """Return the dotted-string form of `event.category` whether it's
    an EventCategory enum or already a raw string."""
    cat = event.category
    return cat.value if hasattr(cat, "value") else str(cat)


def _severity_value(event: Event) -> str:
    sev = event.severity
    return sev.value if hasattr(sev, "value") else str(sev)


def event_to_ocsf(
    event: Event,
    *,
    product_name: str = _DEFAULT_PRODUCT_NAME,
    product_vendor: str = _DEFAULT_PRODUCT_VENDOR,
    product_version: str = _DEFAULT_PRODUCT_VERSION,
    schema_version: str = _DEFAULT_SCHEMA_VERSION,
) -> dict:
    """Return the OCSF-shaped dict for one AEGIS event.

    The contract: every dict that comes out has at minimum
    `category_uid`, `class_uid`, `activity_id`, `type_uid`, `time`,
    `severity_id`, `metadata.version`, `metadata.product.name`. Any
    AEGIS-specific data lands under `unmapped` so SIEMs that ingest
    the JSON can route on it without losing fidelity.
    """
    category_str = _category_value(event)
    category_uid, class_uid, activity_id = _EVENT_MAP.get(
        category_str, _DEFAULT_TRIPLE,
    )
    type_uid = class_uid * 100 + activity_id

    severity_id, severity_name = _SEVERITY_MAP.get(
        _severity_value(event), (0, "Unknown"),
    )

    out: dict = {
        "category_uid": category_uid,
        "category_name": _CATEGORY_NAMES.get(category_uid, "Unknown"),
        "class_uid": class_uid,
        "class_name": _CLASS_NAMES.get(class_uid, "Unknown"),
        "activity_id": activity_id,
        "activity_name": _ACTIVITY_NAMES.get(
            (class_uid, activity_id), "Unknown",
        ),
        "type_uid": type_uid,
        # OCSF expects `time` in milliseconds since epoch.
        "time": int(event.timestamp * 1000),
        "severity_id": severity_id,
        "severity": severity_name,
        "metadata": {
            "version": schema_version,
            "product": {
                "name": product_name,
                "vendor_name": product_vendor,
                "version": product_version,
            },
            "uid": event.event_id,
            "log_name": "aegis.events",
            "original_time": event.timestamp,
        },
        "message": _summarise(event),
        "unmapped": {
            "aegis_category": category_str,
            "aegis_severity": _severity_value(event),
            "aegis_source": event.source,
            "aegis_hostname": event.hostname,
            "aegis_event_id": event.event_id,
            "aegis_data": dict(event.data) if event.data else {},
        },
    }

    mitre = (event.mitre_attack or "").strip()
    if mitre:
        out["attacks"] = [{
            "version": "v15",
            "tactics": [],
            "technique": {"uid": mitre, "name": mitre},
        }]

    # Convenience: lift commonly-queried fields into top-level OCSF
    # observables so dashboards don't have to dig into `unmapped`.
    file_path = (event.data or {}).get("filepath") or (event.data or {}).get("path")
    if file_path:
        out["file"] = {"path": str(file_path), "name": str(file_path).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]}
    pid = (event.data or {}).get("pid")
    if isinstance(pid, int):
        out["process"] = {
            "pid": pid,
            "name": str((event.data or {}).get("name", "")),
            "cmd_line": str((event.data or {}).get("cmdline", "") or "")[:1024],
        }

    return out


def _summarise(event: Event) -> str:
    d = event.data or {}
    rule = d.get("rule_name") or d.get("rule_id") or d.get("rule") or ""
    cat = _category_value(event)
    sev = _severity_value(event).upper()
    if rule:
        return f"AEGIS [{sev}] {cat}: {rule}"
    return f"AEGIS [{sev}] {cat}"


# Convenience helpers exposed for tests + introspection.
def supported_categories() -> list[str]:
    """Every AEGIS category value that has an explicit OCSF mapping."""
    return sorted(_EVENT_MAP.keys())


def mapping_for(aegis_category: str) -> Optional[tuple[int, int, int]]:
    """Return (category_uid, class_uid, activity_id) for an AEGIS
    category, or None if it would fall back to the catch-all."""
    return _EVENT_MAP.get(aegis_category)
