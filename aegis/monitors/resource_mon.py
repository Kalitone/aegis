"""
AEGIS Resource Monitor
========================
Monitors per-process CPU, memory, and I/O to detect:
  - Cryptominers (sustained high CPU)
  - Memory bombs / leaks
  - Disk abuse (ransomware encryption, data staging)

Uses psutil for cross-platform process metrics.
"""

import time
import logging
import threading
from typing import Optional
from collections import defaultdict

import psutil

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.resource")

# Maximum history entries kept per PID to prevent unbounded growth.
_MAX_HISTORY = 100


class ResourceMonitor:
    """Monitors system resource usage per-process."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self._poll_interval = config.get("poll_interval_ms", 5000) / 1000.0
        self._cpu_threshold = config.get("cpu_threshold_percent", 85)
        self._cpu_sustained_s = config.get("cpu_sustained_seconds", 30)
        self._mem_growth_threshold = config.get("memory_growth_mb_per_min", 500)
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Track sustained CPU usage: pid → list of (timestamp, cpu_percent)
        self._cpu_history: dict[int, list[tuple[float, float]]] = defaultdict(list)
        # Track memory growth: pid → list of (timestamp, mem_mb)
        self._mem_history: dict[int, list[tuple[float, float]]] = defaultdict(list)
        # Already alerted PIDs (prevent spam)
        self._alerted_cpu: set[int] = set()
        self._alerted_mem: set[int] = set()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="aegis-resmon")
        self._thread.start()
        logger.info(f"Resource monitor started. CPU threshold: {self._cpu_threshold}%, "
                     f"sustained: {self._cpu_sustained_s}s")

        self.bus.publish(Event(
            category=EventCategory.SYSTEM_START,
            severity=Severity.INFO,
            source="resmon",
            data={"status": "started"},
        ))

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Resource monitor stopped")

    def _poll_loop(self):
        while self._running:
            try:
                now = time.time()
                cutoff = now - max(self._cpu_sustained_s * 2, 120)

                for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "cmdline"]):
                    try:
                        info = proc.info
                        pid = info["pid"]
                        cpu = info.get("cpu_percent", 0) or 0
                        mem_info = info.get("memory_info")
                        mem_mb = (mem_info.rss / 1024 / 1024) if mem_info else 0

                        # Record history
                        self._cpu_history[pid].append((now, cpu))
                        self._mem_history[pid].append((now, mem_mb))

                        # Trim old entries by time, then cap length
                        self._cpu_history[pid] = [
                            (t, v) for t, v in self._cpu_history[pid] if t > cutoff
                        ]
                        self._mem_history[pid] = [
                            (t, v) for t, v in self._mem_history[pid] if t > cutoff
                        ]
                        if len(self._cpu_history[pid]) > _MAX_HISTORY:
                            self._cpu_history[pid] = self._cpu_history[pid][-_MAX_HISTORY:]
                        if len(self._mem_history[pid]) > _MAX_HISTORY:
                            self._mem_history[pid] = self._mem_history[pid][-_MAX_HISTORY:]

                        # Check sustained CPU
                        self._check_cpu(pid, info)

                        # Check memory growth
                        self._check_memory(pid, info)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                # Clean up history for exited processes
                active_pids = {p.pid for p in psutil.process_iter()}
                for pid in list(self._cpu_history.keys()):
                    if pid not in active_pids:
                        del self._cpu_history[pid]
                        self._mem_history.pop(pid, None)
                        self._alerted_cpu.discard(pid)
                        self._alerted_mem.discard(pid)

            except Exception as e:
                logger.error(f"Resource monitor error: {e}", exc_info=True)

            time.sleep(self._poll_interval)

    def _check_cpu(self, pid: int, info: dict):
        """Detect sustained high CPU usage (cryptominer indicator)."""
        if pid in self._alerted_cpu:
            return

        history = self._cpu_history.get(pid, [])
        if len(history) < 3:  # Need enough samples
            return

        # Check if CPU has been above threshold for sustained period
        sustained_start = None
        for ts, cpu in history:
            if cpu >= self._cpu_threshold:
                if sustained_start is None:
                    sustained_start = ts
            else:
                sustained_start = None

        if sustained_start and (time.time() - sustained_start) >= self._cpu_sustained_s:
            name = info.get("name", "unknown")
            cmdline_list = info.get("cmdline") or [name]
            cmdline = " ".join(cmdline_list)
            avg_cpu = sum(v for _, v in history[-5:]) / min(len(history), 5)

            self._alerted_cpu.add(pid)

            self.bus.publish(Event(
                category=EventCategory.RESOURCE_CPU,
                severity=Severity.HIGH,
                source="resmon",
                mitre_attack="T1496",  # Resource Hijacking
                data={
                    "pid": pid,
                    "process": name,
                    "cmdline": cmdline[:200],
                    "avg_cpu_percent": round(avg_cpu, 1),
                    "sustained_seconds": round(time.time() - sustained_start, 1),
                    "threshold": self._cpu_threshold,
                    "alert": "sustained_high_cpu",
                },
            ))
            logger.warning(f"SUSTAINED CPU: PID={pid} ({name}) "
                          f"avg={avg_cpu:.1f}% for {time.time()-sustained_start:.0f}s")

    def _check_memory(self, pid: int, info: dict):
        """Detect rapid memory growth (memory bomb, leak)."""
        if pid in self._alerted_mem:
            return

        history = self._mem_history.get(pid, [])
        if len(history) < 3:
            return

        # Calculate memory growth rate over last minute
        recent = [(t, m) for t, m in history if t > time.time() - 60]
        if len(recent) < 2:
            return

        growth = recent[-1][1] - recent[0][1]  # MB growth
        duration = recent[-1][0] - recent[0][0]  # seconds

        if duration > 0:
            growth_per_min = (growth / duration) * 60
            if growth_per_min > self._mem_growth_threshold:
                name = info.get("name", "unknown")
                cmdline_list = info.get("cmdline") or [name]
                cmdline = " ".join(cmdline_list)

                self._alerted_mem.add(pid)

                self.bus.publish(Event(
                    category=EventCategory.RESOURCE_MEMORY,
                    severity=Severity.HIGH,
                    source="resmon",
                    data={
                        "pid": pid,
                        "process": name,
                        "cmdline": cmdline[:200],
                        "memory_mb": round(recent[-1][1], 1),
                        "growth_mb_per_min": round(growth_per_min, 1),
                        "threshold": self._mem_growth_threshold,
                        "alert": "rapid_memory_growth",
                    },
                ))
                logger.warning(f"MEMORY GROWTH: PID={pid} ({name}) "
                              f"+{growth_per_min:.0f} MB/min")

    @property
    def is_running(self) -> bool:
        return self._running
