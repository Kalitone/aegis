"""
AEGIS MITRE ATT&CK Coverage
============================
Aggregates every technique ID referenced anywhere in the codebase (behavioral
rules, YARA rule meta, hardcoded process-monitor mappings, persistence
monitor mappings, supply-chain detections) and grades it against a curated
"techniques worth caring about" list.

Output is a dict suitable for direct rendering as a heatmap. The web
dashboard at /coverage uses it; the CLI `python -m aegis --coverage` prints
the same data as text.

This is intentionally NOT a real ATT&CK Navigator export. We don't ship the
full STIX bundle (~2 MB) — the curated list below is the slice that matters
for an endpoint EDR. If you want full Navigator JSON, generate it from the
returned dict.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict

logger = logging.getLogger("aegis.utils.mitre_coverage")


# Curated subset — the techniques most relevant to a host-based EDR.
# tactic → {technique_id: friendly_name}
TRACKED_TECHNIQUES: dict[str, dict[str, str]] = {
    "Initial Access": {
        "T1566.001": "Spearphishing Attachment",
        "T1566.002": "Spearphishing Link",
        "T1078":     "Valid Accounts",
        "T1190":     "Exploit Public-Facing App",
    },
    "Execution": {
        "T1059":     "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1059.003": "Windows Command Shell",
        "T1059.004": "Unix Shell",
        "T1059.005": "Visual Basic",
        "T1059.006": "Python",
        "T1059.007": "JavaScript",
        "T1053.003": "Cron",
        "T1053.005": "Scheduled Task",
        "T1204":     "User Execution",
    },
    "Persistence": {
        "T1037":     "Boot or Logon Init Scripts",
        "T1543.002": "Systemd Service",
        "T1543.003": "Windows Service",
        "T1546.003": "WMI Event Subscription",
        "T1546.004": "Unix Shell Config Mod",
        "T1546.010": "AppInit DLLs",
        "T1546.012": "IFEO Injection",
        "T1547.001": "Registry Run Keys / Startup Folder",
    },
    "Privilege Escalation": {
        "T1548.001": "Setuid and Setgid",
        "T1068":     "Exploitation for Priv Esc",
        "T1574.006": "LD_PRELOAD",
        "T1134":     "Access Token Manipulation",
    },
    "Defense Evasion": {
        "T1027":     "Obfuscated Files or Information",
        "T1036.001": "Invalid Code Signature",
        "T1055":     "Process Injection",
        "T1070":     "Indicator Removal on Host",
        "T1112":     "Modify Registry",
        "T1140":     "Deobfuscate / Decode",
    },
    "Credential Access": {
        "T1003":     "OS Credential Dumping",
        "T1552":     "Unsecured Credentials",
        "T1556":     "Modify Authentication Process",
    },
    "Discovery": {
        "T1057":     "Process Discovery",
        "T1082":     "System Information Discovery",
        "T1083":     "File and Directory Discovery",
    },
    "Lateral Movement": {
        "T1021":     "Remote Services",
        "T1563.001": "SSH Hijacking",
    },
    "Collection": {
        "T1074.001": "Local Data Staging",
        "T1005":     "Data from Local System",
    },
    "Command and Control": {
        "T1071":     "Application Layer Protocol",
        "T1071.001": "Web Protocols",
        "T1071.004": "DNS",
        "T1105":     "Ingress Tool Transfer",
        "T1573":     "Encrypted Channel",
    },
    "Exfiltration": {
        "T1041":     "Exfil Over C2 Channel",
        "T1048":     "Exfil Over Alt Protocol",
    },
    "Impact": {
        "T1485":     "Data Destruction",
        "T1486":     "Data Encrypted for Impact",
        "T1496":     "Resource Hijacking",
        "T1611":     "Container Escape",
    },
    "Supply Chain": {
        "T1195.002": "Compromise Software Supply Chain",
    },
}


def _all_tracked_ids() -> set[str]:
    return {tid for d in TRACKED_TECHNIQUES.values() for tid in d}


def _collect_covered_ids() -> set[str]:
    """Walk every detection rule we ship and pull out MITRE IDs."""
    covered: set[str] = set()

    # Behavioral rules
    try:
        from aegis.detection.behavioral import RULES as BRULES
        for r in BRULES:
            if r.mitre_attack:
                covered.add(r.mitre_attack)
    except Exception as e:
        logger.debug(f"behavioral rule scan failed: {e}")

    # YARA built-in rules — we can grep the source for `mitre = "..."`.
    try:
        import re
        from aegis.detection import yara_scanner as _y
        src = _y.BUILTIN_RULES
        covered.update(re.findall(r'mitre\s*=\s*"([^"]+)"', src))
    except Exception as e:
        logger.debug(f"yara meta scan failed: {e}")

    # Hard-coded mappings in process_mon (LD_PRELOAD, cron, miner, etc.)
    covered.update({
        "T1059", "T1059.004", "T1496", "T1574.006", "T1053.003",
    })
    # Persistence monitor MITRE map.
    try:
        from aegis.monitors.persistence import PersistenceMonitor as _PM
        for cat in ("reg::Run", "reg::IFEO_Debuggers", "reg::AppInit",
                    "scheduled_tasks", "services", "wmi_subscriptions",
                    "startup_dirs", "systemd_enabled", "files", "dirs"):
            covered.add(_PM._mitre_for(cat))
    except Exception:
        pass
    # Supply-chain
    covered.add("T1195.002")
    # Authenticode
    covered.add("T1036.001")
    # YARA memory scan default
    covered.add("T1055")
    # Threat-intel C2 lookups
    covered.update({"T1071", "T1071.004", "T1027"})
    return covered


def build_coverage() -> dict:
    """Return {by_tactic: {...}, covered_count, total_count, percent,
    untracked_covered: [...]}"""
    covered = _collect_covered_ids()
    by_tactic: dict[str, dict[str, dict]] = {}
    covered_count = 0
    total = 0
    for tactic, techs in TRACKED_TECHNIQUES.items():
        by_tactic[tactic] = {}
        for tid, name in techs.items():
            total += 1
            is_cov = tid in covered
            if is_cov:
                covered_count += 1
            by_tactic[tactic][tid] = {"name": name, "covered": is_cov}
    untracked = sorted(covered - _all_tracked_ids())
    return {
        "by_tactic": by_tactic,
        "covered_count": covered_count,
        "total_count": total,
        "percent": round(100.0 * covered_count / max(total, 1), 1),
        "untracked_covered": untracked,
    }


def render_text() -> str:
    """ASCII heatmap for the CLI."""
    cov = build_coverage()
    lines = [f"AEGIS MITRE ATT&CK Coverage — "
             f"{cov['covered_count']}/{cov['total_count']} ({cov['percent']}%)",
             "=" * 70]
    for tactic, techs in cov["by_tactic"].items():
        hit = sum(1 for t in techs.values() if t["covered"])
        lines.append(f"\n{tactic}  ({hit}/{len(techs)})")
        for tid, meta in techs.items():
            mark = "✔" if meta["covered"] else "·"
            lines.append(f"  [{mark}] {tid:12s} {meta['name']}")
    if cov["untracked_covered"]:
        lines.append("\nCovered but not in tracked list:")
        for tid in cov["untracked_covered"]:
            lines.append(f"  · {tid}")
    return "\n".join(lines)


def render_navigator_json() -> str:
    """Minimal MITRE ATT&CK Navigator-compatible layer JSON."""
    cov = build_coverage()
    techniques = []
    for tactic, techs in cov["by_tactic"].items():
        for tid, meta in techs.items():
            techniques.append({
                "techniqueID": tid,
                "score": 100 if meta["covered"] else 0,
                "color": "",
                "comment": "AEGIS coverage",
                "enabled": True,
                "metadata": [{"name": "name", "value": meta["name"]}],
            })
    layer = {
        "name": "AEGIS Coverage",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated from AEGIS rules",
        "techniques": techniques,
        "gradient": {"colors": ["#dddddd", "#22c55e"], "minValue": 0, "maxValue": 100},
    }
    return json.dumps(layer, indent=2)


__all__ = ["build_coverage", "render_text", "render_navigator_json",
           "TRACKED_TECHNIQUES"]
