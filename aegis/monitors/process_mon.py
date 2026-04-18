"""
AEGIS Process Monitor
======================
Polls /proc (Linux) or uses psutil (cross-platform) to track process lifecycle.
Detects new processes, unexpected parent-child relationships, and suspicious command lines.

Design: Uses psutil for cross-platform support (Windows + Linux + macOS).
Polling-based rather than event-based because:
  - Works without kernel modules
  - Works inside containers/gVisor
  - psutil's process_iter() is efficient (~2ms per poll)

Inspired by: Sysmon (Windows), Osquery, Velociraptor
"""

import os
import time
import math
import logging
import threading
from typing import Optional
from dataclasses import dataclass, field

import psutil

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.process")


@dataclass
class ProcessSnapshot:
    """Point-in-time snapshot of a process."""
    pid: int
    ppid: int
    name: str
    cmdline: str
    username: str
    create_time: float
    exe: str
    cwd: str
    status: str
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    num_fds: int = 0
    children_pids: list[int] = field(default_factory=list)
    environ: dict = field(default_factory=dict)


def _safe_proc_info(proc: psutil.Process) -> Optional[ProcessSnapshot]:
    """Extract process info safely — processes can exit mid-read."""
    try:
        # num_fds is POSIX-only; Windows uses num_handles.
        fd_attr = "num_handles" if os.name == "nt" else "num_fds"
        info = proc.as_dict(attrs=[
            "pid", "ppid", "name", "cmdline", "username",
            "create_time", "exe", "cwd", "status",
            "cpu_percent", "memory_info", fd_attr,
        ])

        cmdline_list = info.get("cmdline") or []
        cmdline = " ".join(cmdline_list) if cmdline_list else info.get("name", "")

        mem = info.get("memory_info")
        mem_mb = (mem.rss / 1024 / 1024) if mem else 0

        children = []
        try:
            children = [c.pid for c in proc.children()]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        environ = {}
        try:
            environ = proc.environ()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return ProcessSnapshot(
            pid=info["pid"],
            ppid=info.get("ppid", 0),
            name=info.get("name", ""),
            cmdline=cmdline,
            username=info.get("username", ""),
            create_time=info.get("create_time", 0),
            exe=info.get("exe", "") or "",
            cwd=info.get("cwd", "") or "",
            status=info.get("status", ""),
            cpu_percent=info.get("cpu_percent", 0),
            memory_mb=round(mem_mb, 2),
            num_fds=info.get(fd_attr, 0) or 0,
            children_pids=children,
            environ=environ,
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def cmdline_entropy(cmdline: str) -> float:
    """
    Calculate Shannon entropy of a command line string.
    High entropy may indicate encoded/obfuscated commands (base64, hex, etc.)
    """
    if not cmdline:
        return 0.0
    freq = {}
    for c in cmdline:
        freq[c] = freq.get(c, 0) + 1
    length = len(cmdline)
    entropy = -sum((count / length) * math.log2(count / length)
                    for count in freq.values())
    return round(entropy, 3)


# Patterns that are suspicious in command lines
SUSPICIOUS_PATTERNS = [
    # Reverse shells
    "/dev/tcp/",
    "bash -i",
    "nc -e",
    "ncat -e",
    "socat exec",
    "python -c",
    "perl -e",
    "ruby -e",
    # Encoded execution
    "base64 -d",
    "base64 --decode",
    "eval(",
    # Download & execute
    "curl.*|.*sh",
    "wget.*|.*sh",
    "curl.*|.*bash",
    "wget.*|.*bash",
    # Privilege escalation
    "sudo -s",
    "pkexec",
    # Credential access
    "/etc/shadow",
    "/etc/passwd",
    "mimikatz",
    "sekurlsa",
    # Persistence
    "crontab -",
    "/etc/cron",
    ".bashrc",
    ".profile",
    "systemctl enable",
    # Mining
    "stratum+tcp",
    "xmrig",
    "minerd",
    "cpuminer",
    # LD_PRELOAD hijacking
    "LD_PRELOAD",
    "ld.so.preload",
]


class ProcessMonitor:
    """
    Cross-platform process monitor using psutil.
    Detects new processes, tracks lifecycle, flags suspicious behavior.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self._known_pids: dict[int, ProcessSnapshot] = {}
        self._poll_interval = config.get("poll_interval_ms", 500) / 1000.0
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start process monitoring in a background thread."""
        self._running = True
        # Initial snapshot of all processes
        self._refresh_known()
        logger.info(f"Process monitor started. Tracking {len(self._known_pids)} processes. "
                     f"Poll interval: {self._poll_interval}s")

        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="aegis-procmon")
        self._thread.start()

        self.bus.publish(Event(
            category=EventCategory.SYSTEM_START,
            severity=Severity.INFO,
            source="procmon",
            data={"tracked_processes": len(self._known_pids), "status": "started"},
        ))

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Process monitor stopped")

    def _refresh_known(self):
        """Take a snapshot of all current processes."""
        for proc in psutil.process_iter():
            snap = _safe_proc_info(proc)
            if snap:
                self._known_pids[snap.pid] = snap

    def _poll_loop(self):
        """Main polling loop — detect new and exited processes."""
        while self._running:
            try:
                current_pids: dict[int, ProcessSnapshot] = {}
                for proc in psutil.process_iter():
                    snap = _safe_proc_info(proc)
                    if snap:
                        current_pids[snap.pid] = snap

                # Detect new processes
                for pid, snap in current_pids.items():
                    if pid not in self._known_pids:
                        self._handle_new_process(snap)

                # Detect exited processes
                for pid, snap in self._known_pids.items():
                    if pid not in current_pids:
                        self._handle_exit_process(snap)

                self._known_pids = current_pids

            except Exception as e:
                logger.error(f"Process monitor poll error: {e}", exc_info=True)

            time.sleep(self._poll_interval)

    def _handle_new_process(self, snap: ProcessSnapshot):
        """Evaluate a newly detected process."""
        severity = Severity.INFO
        mitre = ""
        suspicious_matches = []

        # Check command line against suspicious patterns
        cmdline_lower = snap.cmdline.lower()
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in cmdline_lower:
                suspicious_matches.append(pattern)

        # Check for high entropy command lines (possible obfuscation)
        entropy = cmdline_entropy(snap.cmdline)

        # Check for LD_PRELOAD in environment
        ld_preload = snap.environ.get("LD_PRELOAD", "")

        # Determine severity
        if suspicious_matches:
            severity = Severity.HIGH
            # Specific MITRE mappings
            if any(p in cmdline_lower for p in ["/dev/tcp", "nc -e", "ncat", "socat"]):
                severity = Severity.CRITICAL
                mitre = "T1059.004"  # Command and Scripting Interpreter: Unix Shell
            elif any(p in cmdline_lower for p in ["crontab", "/etc/cron", ".bashrc"]):
                mitre = "T1053.003"  # Scheduled Task/Job: Cron
            elif any(p in cmdline_lower for p in ["xmrig", "stratum", "minerd"]):
                severity = Severity.HIGH
                mitre = "T1496"  # Resource Hijacking
            elif any(p in cmdline_lower for p in ["base64", "eval("]):
                mitre = "T1059"  # Command and Scripting Interpreter

        if ld_preload:
            severity = Severity.CRITICAL
            mitre = "T1574.006"  # Hijack Execution Flow: Dynamic Linker Hijacking
            suspicious_matches.append(f"LD_PRELOAD={ld_preload}")

        # Authenticode triage (Windows only, soft-fail elsewhere). An unsigned
        # binary in %TEMP% / %APPDATA% is a CRITICAL escalation regardless of
        # what its cmdline looks like — kills most commodity malware.
        sig_info = {}
        if os.name == "nt" and snap.exe:
            try:
                from aegis.utils.authenticode import triage as _ac_triage
                sig_info = _ac_triage(snap.exe)
                if sig_info.get("severity") == "critical":
                    severity = Severity.CRITICAL
                    suspicious_matches.append(f"authenticode:{sig_info['reason']}")
                    if not mitre:
                        mitre = "T1036.001"  # Masquerading: Invalid Code Signature
                elif sig_info.get("severity") == "medium" and severity == Severity.INFO:
                    severity = Severity.LOW
                    suspicious_matches.append(f"authenticode:{sig_info['reason']}")
            except Exception as e:
                logger.debug(f"authenticode triage failed for {snap.exe}: {e}")

        category = (EventCategory.PROC_SUSPICIOUS if severity in (Severity.CRITICAL, Severity.HIGH)
                     else EventCategory.PROC_CREATE)

        self.bus.publish(Event(
            category=category,
            severity=severity,
            source="procmon",
            mitre_attack=mitre,
            data={
                "pid": snap.pid,
                "ppid": snap.ppid,
                "name": snap.name,
                "cmdline": snap.cmdline,
                "exe": snap.exe,
                "cwd": snap.cwd,
                "username": snap.username,
                "cpu_percent": snap.cpu_percent,
                "memory_mb": snap.memory_mb,
                "cmdline_entropy": entropy,
                "suspicious_patterns": suspicious_matches,
                "ld_preload": ld_preload,
                "create_time": snap.create_time,
                "authenticode": sig_info,
            },
        ))

        if suspicious_matches:
            logger.warning(f"SUSPICIOUS PROCESS: PID={snap.pid} CMD='{snap.cmdline[:100]}' "
                          f"MATCHES={suspicious_matches}")

    def _handle_exit_process(self, snap: ProcessSnapshot):
        """Log process exit."""
        self.bus.publish(Event(
            category=EventCategory.PROC_EXIT,
            severity=Severity.INFO,
            source="procmon",
            data={
                "pid": snap.pid,
                "name": snap.name,
                "cmdline": snap.cmdline[:200],
            },
        ))

    @property
    def tracked_count(self) -> int:
        return len(self._known_pids)

    @property
    def is_running(self) -> bool:
        return self._running
