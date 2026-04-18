"""
AEGIS Persistence Monitor
==========================
Snapshots every well-known persistence surface on the host and alerts on
diff. This is the single highest-leverage Windows EDR check after process
monitoring — most post-exploitation actors install persistence within
minutes, and the surface (Run keys, services, scheduled tasks, WMI
subscriptions, IFEO, AppInit_DLLs, startup folders) is small and well
documented.

References:
  - MITRE ATT&CK T1547 (Boot or Logon Autostart Execution)
  - MITRE ATT&CK T1546 (Event-triggered Execution)
  - MITRE ATT&CK T1053 (Scheduled Task/Job)
  - Microsoft Sysinternals Autoruns (the gold standard list of locations
    we partially mirror).

Linux: cron, systemd units, /etc/profile.d, ld.so.preload, init.d.
"""

from __future__ import annotations

import os
import json
import time
import logging
import threading
import platform
import subprocess
from pathlib import Path

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.persistence")

WINDOWS_RUN_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

WINDOWS_IFEO_ROOT = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
WINDOWS_APPINIT   = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
WINDOWS_STARTUP_DIRS = [
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
]

LINUX_PERSISTENCE_FILES = [
    "/etc/crontab",
    "/etc/ld.so.preload",
    "/etc/rc.local",
    "/etc/profile",
]
LINUX_PERSISTENCE_DIRS = [
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/etc/cron.weekly", "/etc/cron.monthly",
    "/etc/profile.d",
    "/etc/systemd/system",
    "/etc/init.d",
    "/var/spool/cron",
]


def _run(cmd: list[str], timeout: int = 30) -> str:
    """Run a command, return stdout (or empty on failure)."""
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="ignore",
        )
        return res.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug(f"persistence command failed {cmd[0]}: {e}")
        return ""


# ── Windows snapshot helpers ──────────────────────────────────────

def _snapshot_registry_key(path: str) -> dict[str, str]:
    """Return {value_name: value_data} for one registry key."""
    out = _run(["reg", "query", path], timeout=10)
    entries: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        # Skip key-name lines (start with HKLM/HKCU) and blank lines.
        if not line or line.startswith(("HKEY_", "HKLM", "HKCU", "End of search")):
            continue
        # "Name    REG_TYPE    Data" — split conservatively on multi-space.
        parts = line.split(None, 2)
        if len(parts) >= 3 and parts[1].startswith("REG_"):
            entries[parts[0]] = parts[2]
    return entries


def _snapshot_ifeo() -> dict[str, str]:
    """Image File Execution Options 'Debugger' values are a classic
    persistence + privesc trick: any sethc.exe / utilman.exe debugger entry
    redirects accessibility tools to attacker code at the login screen."""
    out = _run(["reg", "query", WINDOWS_IFEO_ROOT, "/s", "/v", "Debugger"], timeout=20)
    entries: dict[str, str] = {}
    current_key = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith(("HKEY_", "HKLM")):
            current_key = s
        elif s.lower().startswith("debugger") and current_key:
            parts = s.split(None, 2)
            if len(parts) >= 3:
                entries[current_key] = parts[2]
    return entries


def _snapshot_appinit() -> dict[str, str]:
    out = _run(["reg", "query", WINDOWS_APPINIT, "/v", "AppInit_DLLs"], timeout=10)
    entries: dict[str, str] = {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("AppInit_DLLs"):
            parts = s.split(None, 2)
            if len(parts) >= 3 and parts[2].strip():
                entries["AppInit_DLLs"] = parts[2]
    return entries


def _snapshot_scheduled_tasks() -> dict[str, str]:
    """Use schtasks to enumerate non-Microsoft scheduled tasks."""
    out = _run(["schtasks", "/Query", "/FO", "CSV", "/V"], timeout=60)
    tasks: dict[str, str] = {}
    for line in out.splitlines()[1:]:
        # Keep it light: name + action is enough as a fingerprint.
        cols = [c.strip('"') for c in line.split('","')]
        if len(cols) > 8:
            name = cols[1]
            action = cols[8] if len(cols) > 8 else ""
            if name and not name.startswith(r"\Microsoft\Windows"):
                tasks[name] = action
    return tasks


def _snapshot_services() -> dict[str, str]:
    """Use sc.exe to enumerate service binary paths. Same caveat: large output,
    we keep just name → ImagePath."""
    out = _run(["sc", "queryex", "type=", "service", "state=", "all"], timeout=60)
    names = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("SERVICE_NAME:"):
            names.append(s.split(":", 1)[1].strip())
    services: dict[str, str] = {}
    # Resolve binary path per service. This is N×reg-query but services
    # change rarely — we run snapshots on a slow timer.
    for name in names:
        path = _run(["sc", "qc", name], timeout=10)
        for line in path.splitlines():
            if "BINARY_PATH_NAME" in line:
                services[name] = line.split(":", 1)[1].strip()
                break
    return services


def _snapshot_startup_dirs() -> dict[str, str]:
    """Enumerate files in user/all-user startup folders."""
    entries: dict[str, str] = {}
    for tmpl in WINDOWS_STARTUP_DIRS:
        path = Path(os.path.expandvars(tmpl))
        if not path.exists():
            continue
        for p in path.iterdir():
            if p.is_file():
                try:
                    entries[str(p)] = str(p.stat().st_mtime)
                except OSError:
                    pass
    return entries


def _snapshot_wmi_subscriptions() -> dict[str, str]:
    """WMI permanent event subscriptions — used by SeaDuke, NotPetya,
    POSHSPY, et al. Stable, low-noise persistence."""
    ps = ("Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding "
          "| Select-Object Filter, Consumer | ConvertTo-Json -Compress")
    out = _run(["powershell", "-NoProfile", "-Command", ps], timeout=30)
    out = out.strip()
    if not out or out == "null":
        return {}
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return {str(d.get("Filter", "?")): str(d.get("Consumer", "?")) for d in data}
    except json.JSONDecodeError:
        return {}


def snapshot_windows() -> dict[str, dict[str, str]]:
    snap: dict[str, dict[str, str]] = {}
    for key in WINDOWS_RUN_KEYS:
        snap[f"reg::{key}"] = _snapshot_registry_key(key)
    snap["reg::IFEO_Debuggers"] = _snapshot_ifeo()
    snap["reg::AppInit"] = _snapshot_appinit()
    snap["scheduled_tasks"] = _snapshot_scheduled_tasks()
    snap["services"] = _snapshot_services()
    snap["startup_dirs"] = _snapshot_startup_dirs()
    snap["wmi_subscriptions"] = _snapshot_wmi_subscriptions()
    return snap


# ── Linux snapshot helpers ────────────────────────────────────────

def snapshot_linux() -> dict[str, dict[str, str]]:
    snap: dict[str, dict[str, str]] = {"files": {}, "dirs": {}}
    for f in LINUX_PERSISTENCE_FILES:
        p = Path(f)
        if p.exists():
            try:
                snap["files"][f] = f"{p.stat().st_mtime}:{p.stat().st_size}"
            except OSError:
                pass
    for d in LINUX_PERSISTENCE_DIRS:
        dp = Path(d)
        if not dp.exists():
            continue
        for p in dp.iterdir():
            if p.is_file():
                try:
                    snap["dirs"][str(p)] = f"{p.stat().st_mtime}:{p.stat().st_size}"
                except OSError:
                    pass
    # systemctl list-unit-files for enabled services.
    out = _run(["systemctl", "list-unit-files", "--type=service",
                "--state=enabled", "--no-pager", "--no-legend"], timeout=20)
    units: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if parts:
            units[parts[0]] = "enabled"
    snap["systemd_enabled"] = units
    return snap


# ── Severity / triage ─────────────────────────────────────────────

# Categories that map to a CRITICAL persistence vector — anything new here
# is almost always malicious or at least worth waking someone up.
HIGH_SEVERITY_CATEGORIES = {
    "reg::IFEO_Debuggers",
    "reg::AppInit",
    "wmi_subscriptions",
}


def _diff_snapshot(prev: dict, curr: dict) -> list[dict]:
    """Return list of {category, key, change, before, after}."""
    changes: list[dict] = []
    cats = set(prev.keys()) | set(curr.keys())
    for cat in cats:
        before = prev.get(cat, {}) or {}
        after = curr.get(cat, {}) or {}
        for k in after:
            if k not in before:
                changes.append({"category": cat, "key": k, "change": "added",
                                "before": "", "after": str(after[k])[:500]})
            elif before[k] != after[k]:
                changes.append({"category": cat, "key": k, "change": "modified",
                                "before": str(before[k])[:300],
                                "after": str(after[k])[:300]})
        for k in before:
            if k not in after:
                changes.append({"category": cat, "key": k, "change": "removed",
                                "before": str(before[k])[:500], "after": ""})
    return changes


# ── PersistenceMonitor ────────────────────────────────────────────

class PersistenceMonitor:
    """Polls every `poll_interval_seconds` (default 5 min). The first poll
    becomes the baseline — subsequent polls publish detection events for any
    diff."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.platform = platform.system().lower()
        self.poll_interval = float(self.config.get("poll_interval_seconds", 300))
        self.baseline_path = Path(self.config.get("baseline_path",
                                                  "data/persistence.baseline.json"))
        self._prev: dict = {}
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        if not self.config.get("enabled", True):
            logger.info("PersistenceMonitor disabled in config")
            return
        if self.baseline_path.exists():
            try:
                self._prev = json.loads(self.baseline_path.read_text())
                logger.info(f"PersistenceMonitor: loaded baseline ({sum(len(v) for v in self._prev.values())} entries)")
            except Exception as e:
                logger.warning(f"PersistenceMonitor: baseline unreadable, will re-baseline: {e}")
                self._prev = {}
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="aegis-persistence")
        self._thread.start()
        logger.info(f"PersistenceMonitor started ({self.platform}, poll={self.poll_interval}s)")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _snapshot(self) -> dict:
        try:
            if self.platform == "windows":
                return snapshot_windows()
            return snapshot_linux()
        except Exception as e:
            logger.error(f"persistence snapshot failed: {e}", exc_info=True)
            return {}

    def _persist_baseline(self, snap: dict) -> None:
        try:
            self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
            self.baseline_path.write_text(json.dumps(snap, indent=2, default=str))
        except OSError as e:
            logger.warning(f"could not write persistence baseline: {e}")

    def _loop(self):
        while self._running:
            curr = self._snapshot()
            if not curr:
                time.sleep(self.poll_interval)
                continue
            if not self._prev:
                self._prev = curr
                self._persist_baseline(curr)
                logger.info("PersistenceMonitor: baseline established")
            else:
                changes = _diff_snapshot(self._prev, curr)
                for ch in changes:
                    self._publish(ch)
                if changes:
                    self._prev = curr
                    self._persist_baseline(curr)
            # sleep in 1s slices so stop() is responsive
            slept = 0.0
            while self._running and slept < self.poll_interval:
                time.sleep(1.0)
                slept += 1.0

    def _publish(self, change: dict) -> None:
        sev = (Severity.CRITICAL if change["category"] in HIGH_SEVERITY_CATEGORIES
               or change["change"] == "added"
               else Severity.HIGH)
        # Removals of legitimate persistence are noise, downgrade.
        if change["change"] == "removed":
            sev = Severity.MEDIUM
        self.bus.publish(Event(
            category=EventCategory.PROC_SUSPICIOUS,  # closest fit until we add a new category
            severity=sev,
            source="persistence",
            mitre_attack=self._mitre_for(change["category"]),
            data={
                "rule_name": "Persistence change",
                "rule": "PERSIST-001",
                "persistence_category": change["category"],
                "persistence_key": change["key"],
                "change": change["change"],
                "before": change["before"],
                "after": change["after"],
            },
        ))
        logger.warning(f"PERSISTENCE {change['change'].upper()} "
                       f"[{change['category']}] {change['key']} -> {change['after'][:100]}")

    @staticmethod
    def _mitre_for(category: str) -> str:
        if category.startswith("reg::"):
            if "IFEO" in category:
                return "T1546.012"
            if "AppInit" in category:
                return "T1546.010"
            return "T1547.001"
        if category == "scheduled_tasks":
            return "T1053.005"
        if category == "services":
            return "T1543.003"
        if category == "wmi_subscriptions":
            return "T1546.003"
        if category == "startup_dirs":
            return "T1547.001"
        if category == "systemd_enabled":
            return "T1543.002"
        if category in ("files", "dirs"):
            return "T1037"
        return "T1547"

    @property
    def is_running(self) -> bool:
        return self._running
