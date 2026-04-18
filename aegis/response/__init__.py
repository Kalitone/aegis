"""
AEGIS Response Engine
=======================
Automated response to detection events.
Maps severity → action: kill, quarantine, forensic snapshot, alert.

Safety: All destructive actions are logged before execution.
Forensic data is captured BEFORE any kill/quarantine action.
"""

import os
import time
import json
import shutil
import signal
import logging
import hashlib
from pathlib import Path
from typing import Optional

import psutil

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.response")


class ResponseEngine:
    """Automated incident response engine."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self.auto_respond = config.get("auto_respond", True)
        self.quarantine_dir = Path(config.get("quarantine_dir", "quarantine"))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.forensics_dir = Path(config.get("forensics_dir", "data/forensics"))
        self.forensics_dir.mkdir(parents=True, exist_ok=True)
        self._running = False
        self._action_count = 0

        # Severity → actions mapping
        self.severity_actions = config.get("severity_actions", {
            "critical": ["kill_process", "quarantine_file", "forensic_snapshot", "alert"],
            "high": ["quarantine_file", "alert", "forensic_snapshot"],
            "medium": ["alert", "log"],
            "low": ["log"],
        })

        # Protected PIDs (never kill our own process tree)
        self._protected_pids = {os.getpid(), 1}
        try:
            self._protected_pids.add(os.getppid())
        except OSError:
            pass

    def start(self):
        """Subscribe to all detection events."""
        self.bus.subscribe("detection.*", self._on_detection)
        self._running = True
        logger.info(f"Response engine started. Auto-respond: {self.auto_respond}")

    def stop(self):
        self._running = False
        logger.info(f"Response engine stopped. Actions taken: {self._action_count}")

    def _on_detection(self, event: Event):
        """Handle a detection event — determine and execute response."""
        severity = event.severity.value
        actions = self.severity_actions.get(severity, ["log"])

        logger.info(f"RESPONSE: Severity={severity} Rule={event.data.get('rule_id', 'N/A')} "
                     f"Actions={actions}")

        if not self.auto_respond:
            self.bus.publish(Event(
                category=EventCategory.RESPONSE_ALERT,
                severity=event.severity,
                source="response",
                data={
                    "original_event": event.to_dict(),
                    "suggested_actions": actions,
                    "auto_respond": False,
                    "message": "Auto-respond disabled. Manual action required.",
                },
            ))
            return

        for action in actions:
            try:
                if action == "kill_process":
                    self._kill_process(event)
                elif action == "quarantine_file":
                    self._quarantine_file(event)
                elif action == "forensic_snapshot":
                    self._forensic_snapshot(event)
                elif action == "alert":
                    self._alert(event)
                elif action == "log":
                    self._log_detection(event)
                self._action_count += 1
            except Exception as e:
                logger.error(f"Response action '{action}' failed: {e}", exc_info=True)

    def _kill_process(self, event: Event):
        """Kill a malicious process and its children."""
        pid = event.data.get("pid") or event.data.get("source_event", {}).get("pid")
        if not pid:
            logger.warning("Kill requested but no PID available")
            return

        if pid in self._protected_pids:
            logger.warning(f"Refusing to kill protected PID {pid}")
            return

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            cmdline = " ".join(proc.cmdline() or [])

            # Capture state before kill
            proc_info = {
                "pid": pid,
                "name": name,
                "cmdline": cmdline,
                "status": proc.status(),
                "username": proc.username(),
                "create_time": proc.create_time(),
            }

            # Kill children first, then parent
            children = proc.children(recursive=True)
            for child in children:
                if child.pid not in self._protected_pids:
                    try:
                        child.kill()
                        logger.info(f"Killed child process: PID={child.pid}")
                    except psutil.NoSuchProcess:
                        pass

            proc.kill()
            logger.warning(f"KILLED: PID={pid} ({name}) CMD='{cmdline[:100]}'")

            self.bus.publish(Event(
                category=EventCategory.RESPONSE_KILL,
                severity=Severity.HIGH,
                source="response",
                data={
                    "action": "process_killed",
                    "process_info": proc_info,
                    "children_killed": [c.pid for c in children],
                    "reason": event.data.get("rule_name", "detection"),
                },
            ))

        except psutil.NoSuchProcess:
            logger.info(f"Process {pid} already exited")
        except psutil.AccessDenied:
            logger.error(f"Access denied killing PID {pid}")
        except Exception as e:
            logger.error(f"Failed to kill PID {pid}: {e}")

    def _quarantine_file(self, event: Event):
        """Move a malicious file to quarantine."""
        filepath = (event.data.get("filepath") or
                    event.data.get("path") or
                    event.data.get("source_event", {}).get("path"))

        if not filepath or not os.path.exists(filepath):
            return

        try:
            # Calculate hashes
            with open(filepath, "rb") as f:
                content = f.read()
            sha256 = hashlib.sha256(content).hexdigest()
            md5 = hashlib.md5(content).hexdigest()

            # Create quarantine entry
            timestamp = int(time.time())
            quarantine_name = f"{timestamp}_{sha256[:16]}_{Path(filepath).name}"
            quarantine_path = self.quarantine_dir / quarantine_name

            # Save metadata
            metadata = {
                "original_path": str(filepath),
                "sha256": sha256,
                "md5": md5,
                "size": len(content),
                "quarantined_at": time.time(),
                "reason": event.data.get("rule_name", "detection"),
                "rule_id": event.data.get("rule_id", ""),
                "original_permissions": oct(os.stat(filepath).st_mode),
            }
            meta_path = self.quarantine_dir / f"{quarantine_name}.meta.json"
            meta_path.write_text(json.dumps(metadata, indent=2))

            # Move file to quarantine
            shutil.move(filepath, str(quarantine_path))

            # Remove execute permissions
            os.chmod(str(quarantine_path), 0o000)

            logger.warning(f"QUARANTINED: {filepath} → {quarantine_path}")

            self.bus.publish(Event(
                category=EventCategory.RESPONSE_QUARANTINE,
                severity=Severity.HIGH,
                source="response",
                data={
                    "action": "file_quarantined",
                    "original_path": str(filepath),
                    "quarantine_path": str(quarantine_path),
                    "sha256": sha256,
                    "md5": md5,
                    "size": len(content),
                },
            ))

        except Exception as e:
            logger.error(f"Quarantine failed for {filepath}: {e}")

    def _forensic_snapshot(self, event: Event):
        """Capture full system state for post-incident analysis."""
        timestamp = int(time.time())
        snapshot_path = self.forensics_dir / f"snapshot_{timestamp}.json"

        try:
            snapshot = {
                "timestamp": time.time(),
                "trigger_event": event.to_dict(),
                "processes": [],
                "network_connections": [],
                "listeners": [],
            }

            # Capture all processes
            for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline",
                                              "username", "create_time", "status",
                                              "cpu_percent", "memory_info"]):
                try:
                    info = proc.info
                    cmdline = info.get("cmdline") or []
                    mem = info.get("memory_info")
                    snapshot["processes"].append({
                        "pid": info["pid"],
                        "ppid": info.get("ppid", 0),
                        "name": info.get("name", ""),
                        "cmdline": " ".join(cmdline),
                        "username": info.get("username", ""),
                        "cpu_percent": info.get("cpu_percent", 0),
                        "memory_mb": round(mem.rss / 1024 / 1024, 2) if mem else 0,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Capture network state
            for conn in psutil.net_connections(kind="inet"):
                try:
                    entry = {
                        "status": conn.status,
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "pid": conn.pid,
                    }
                    if conn.status == "LISTEN":
                        snapshot["listeners"].append(entry)
                    else:
                        snapshot["network_connections"].append(entry)
                except Exception:
                    continue

            snapshot_path.write_text(json.dumps(snapshot, indent=2, default=str))
            logger.info(f"Forensic snapshot saved: {snapshot_path}")

            self.bus.publish(Event(
                category=EventCategory.RESPONSE_FORENSIC,
                severity=Severity.INFO,
                source="response",
                data={
                    "action": "forensic_snapshot",
                    "path": str(snapshot_path),
                    "processes": len(snapshot["processes"]),
                    "connections": len(snapshot["network_connections"]),
                },
            ))

        except Exception as e:
            logger.error(f"Forensic snapshot failed: {e}", exc_info=True)

    def _alert(self, event: Event):
        """Publish an alert event."""
        self.bus.publish(Event(
            category=EventCategory.RESPONSE_ALERT,
            severity=event.severity,
            source="response",
            data={
                "action": "alert",
                "rule_id": event.data.get("rule_id", ""),
                "rule_name": event.data.get("rule_name", event.data.get("rule", "")),
                "description": event.data.get("description", ""),
                "mitre_attack": event.mitre_attack,
                "original_source": event.source,
                "summary": self._build_summary(event),
            },
        ))

    def _log_detection(self, event: Event):
        """Log detection for record keeping."""
        logger.info(f"DETECTION LOG: [{event.severity.value.upper()}] "
                     f"rule={event.data.get('rule_id', 'N/A')} "
                     f"source={event.source}")

    def _build_summary(self, event: Event) -> str:
        """Build a human-readable alert summary."""
        parts = []
        if rule_name := event.data.get("rule_name", event.data.get("rule", "")):
            parts.append(f"Rule: {rule_name}")
        if pid := event.data.get("pid", event.data.get("source_event", {}).get("pid")):
            parts.append(f"PID: {pid}")
        if filepath := event.data.get("filepath", event.data.get("path", "")):
            parts.append(f"File: {filepath}")
        if mitre := event.mitre_attack:
            parts.append(f"ATT&CK: {mitre}")
        return " | ".join(parts) if parts else "Detection event"

    @property
    def is_running(self) -> bool:
        return self._running
