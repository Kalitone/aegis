"""
AEGIS Network Connection Monitor
==================================
Tracks all TCP/UDP connections, maps them to owning processes,
detects new listeners, suspicious outbound connections, and connection anomalies.

Uses psutil for cross-platform support (parses /proc/net/tcp on Linux,
uses native APIs on Windows/macOS).

Inspired by: Zeek connection logs, CrowdStrike Falcon netmon, Osquery socket_events
"""

import time
import logging
import threading
from typing import Optional
from dataclasses import dataclass

import psutil

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.network")

# Well-known suspicious ports (C2, backdoors, tunneling)
SUSPICIOUS_PORTS = {
    4444, 5555, 1337, 31337,    # Metasploit, common RATs
    6666, 6667, 6668, 6669,      # IRC (C2 channels)
    8888, 9001, 9050, 9150,      # Alt HTTP, Tor
    1234, 3333, 5353,            # Common backdoor ports
    4443, 8443,                  # Alt HTTPS (common C2)
}

# Known safe ports (we still log but lower severity)
TRUSTED_PORTS = {80, 443, 53, 22, 8080}


@dataclass
class ConnectionInfo:
    """A single network connection."""
    proto: str         # "tcp", "tcp6", "udp"
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str        # ESTABLISHED, LISTEN, TIME_WAIT, etc.
    pid: int
    process_name: str
    cmdline: str


def _get_connections() -> list[ConnectionInfo]:
    """Get all current network connections with process info."""
    connections = []
    for conn in psutil.net_connections(kind="inet"):
        try:
            pid = conn.pid or 0
            name = ""
            cmdline = ""
            if pid:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    cmd_list = proc.cmdline()
                    cmdline = " ".join(cmd_list) if cmd_list else name
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            local = conn.laddr
            remote = conn.raddr

            connections.append(ConnectionInfo(
                proto="tcp" if conn.type == 1 else "udp",
                local_addr=local.ip if local else "",
                local_port=local.port if local else 0,
                remote_addr=remote.ip if remote else "",
                remote_port=remote.port if remote else 0,
                status=conn.status,
                pid=pid,
                process_name=name,
                cmdline=cmdline[:200],
            ))
        except Exception:
            continue
    return connections


class NetworkMonitor:
    """
    Monitors network connections for suspicious activity.

    Detects:
      - New listening ports (potential backdoor)
      - Connections to suspicious ports (C2)
      - Connection bursts (beaconing/scanning)
      - Unexpected processes making outbound connections
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self._poll_interval = config.get("poll_interval_ms", 1000) / 1000.0
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Track known state
        self._known_listeners: set[tuple[str, int, int]] = set()   # (addr, port, pid)
        self._known_outbound: set[tuple[int, str, int]] = set()    # (pid, remote_addr, remote_port)
        self._connection_counts: dict[int, int] = {}                # pid → connection count

        # Configurable thresholds
        self._suspicious_ports = SUSPICIOUS_PORTS | set(config.get("suspicious_ports", []))
        self._trusted_ports = TRUSTED_PORTS | set(config.get("trusted_ports", []))

    def start(self):
        self._running = True

        # Baseline current connections
        for conn in _get_connections():
            if conn.status == "LISTEN":
                self._known_listeners.add((conn.local_addr, conn.local_port, conn.pid))
            elif conn.status == "ESTABLISHED" and conn.remote_addr:
                self._known_outbound.add((conn.pid, conn.remote_addr, conn.remote_port))

        logger.info(f"Network monitor started. Known listeners: {len(self._known_listeners)}, "
                     f"outbound: {len(self._known_outbound)}")

        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="aegis-netmon")
        self._thread.start()

        self.bus.publish(Event(
            category=EventCategory.SYSTEM_START,
            severity=Severity.INFO,
            source="netmon",
            data={"listeners": len(self._known_listeners), "status": "started"},
        ))

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Network monitor stopped")

    def _poll_loop(self):
        while self._running:
            try:
                connections = _get_connections()
                current_listeners: set[tuple[str, int, int]] = set()
                current_outbound: set[tuple[int, str, int]] = set()
                pid_conn_count: dict[int, int] = {}

                for conn in connections:
                    if conn.status == "LISTEN":
                        key = (conn.local_addr, conn.local_port, conn.pid)
                        current_listeners.add(key)

                        # Detect new listeners
                        if key not in self._known_listeners:
                            self._handle_new_listener(conn)

                    elif conn.status == "ESTABLISHED" and conn.remote_addr:
                        key = (conn.pid, conn.remote_addr, conn.remote_port)
                        current_outbound.add(key)

                        # Count connections per PID
                        pid_conn_count[conn.pid] = pid_conn_count.get(conn.pid, 0) + 1

                        # Detect new outbound to suspicious destinations
                        if key not in self._known_outbound:
                            self._handle_new_outbound(conn)

                # Detect connection bursts (possible scanning or beaconing)
                for pid, count in pid_conn_count.items():
                    prev_count = self._connection_counts.get(pid, 0)
                    if count - prev_count > 20:  # 20+ new connections in one interval
                        self._handle_connection_burst(pid, count, prev_count)

                self._known_listeners = current_listeners
                self._known_outbound = current_outbound
                self._connection_counts = pid_conn_count

            except Exception as e:
                logger.error(f"Network monitor poll error: {e}", exc_info=True)

            time.sleep(self._poll_interval)

    def _handle_new_listener(self, conn: ConnectionInfo):
        """New listening port detected."""
        severity = Severity.MEDIUM
        mitre = "T1071"  # Application Layer Protocol

        if conn.local_port in self._suspicious_ports:
            severity = Severity.CRITICAL
            mitre = "T1571"  # Non-Standard Port

        self.bus.publish(Event(
            category=EventCategory.NET_LISTEN,
            severity=severity,
            source="netmon",
            mitre_attack=mitre,
            data={
                "local_addr": conn.local_addr,
                "local_port": conn.local_port,
                "pid": conn.pid,
                "process": conn.process_name,
                "cmdline": conn.cmdline,
            },
        ))
        logger.warning(f"NEW LISTENER: {conn.local_addr}:{conn.local_port} "
                       f"PID={conn.pid} ({conn.process_name})")

    def _handle_new_outbound(self, conn: ConnectionInfo):
        """New outbound connection detected."""
        severity = Severity.INFO

        if conn.remote_port in self._suspicious_ports:
            severity = Severity.HIGH

        # Connections to non-standard ports from unexpected processes
        if conn.remote_port not in self._trusted_ports:
            severity = max(severity, Severity.LOW, key=lambda s: ["info","low","medium","high","critical"].index(s.value))

        self.bus.publish(Event(
            category=EventCategory.NET_CONNECT,
            severity=severity,
            source="netmon",
            data={
                "remote_addr": conn.remote_addr,
                "remote_port": conn.remote_port,
                "local_port": conn.local_port,
                "pid": conn.pid,
                "process": conn.process_name,
                "cmdline": conn.cmdline,
                "proto": conn.proto,
            },
        ))

    def _handle_connection_burst(self, pid: int, current: int, previous: int):
        """Sudden spike in connections from a single process."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            cmdline = " ".join(proc.cmdline() or [name])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "unknown"
            cmdline = "unknown"

        self.bus.publish(Event(
            category=EventCategory.NET_CONNECT,
            severity=Severity.HIGH,
            source="netmon",
            mitre_attack="T1046",  # Network Service Discovery
            data={
                "pid": pid,
                "process": name,
                "cmdline": cmdline[:200],
                "connection_count": current,
                "previous_count": previous,
                "burst_delta": current - previous,
                "alert": "connection_burst",
            },
        ))
        logger.warning(f"CONNECTION BURST: PID={pid} ({name}) "
                       f"{previous}→{current} connections")

    @property
    def is_running(self) -> bool:
        return self._running
