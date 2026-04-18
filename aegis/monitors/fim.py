"""
AEGIS File Integrity Monitor (FIM)
===================================
Monitors filesystem for changes using the watchdog library (cross-platform inotify/FSEvents/ReadDirectoryChanges).

On start:
  1. Baselines all files in watched directories (SHA-256 hashes)
  2. Begins real-time monitoring for CREATE, MODIFY, DELETE, MOVE events

On file event:
  1. Computes SHA-256 of new/modified file
  2. Compares against baseline
  3. Publishes event to event bus (triggers YARA scan downstream)

Inspired by: Wazuh FIM, OSSEC syscheck, AIDE
"""

import os
import hashlib
import json
import time
import logging
import threading
import sqlite3
from pathlib import Path
from typing import Optional

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.fim")


def sha256_file(filepath: str, chunk_size: int = 8192) -> Optional[str]:
    """Compute SHA-256 hash of a file. Returns None if file can't be read."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError, FileNotFoundError):
        return None


class FIMHandler(FileSystemEventHandler):
    """Watchdog event handler that publishes to AEGIS event bus."""

    def __init__(self, event_bus: EventBus, baseline_db: "BaselineDB",
                 exclude_patterns: list[str] | None = None):
        super().__init__()
        self.bus = event_bus
        self.baseline = baseline_db
        self.exclude_patterns = exclude_patterns or []
        self._throttle: dict[str, float] = {}
        self._throttle_interval = 1.0  # Ignore duplicate events within 1s

    def _should_exclude(self, path: str) -> bool:
        """Check if path matches any exclude pattern."""
        for pattern in self.exclude_patterns:
            if pattern in path:
                return True
        return False

    def _throttled(self, path: str) -> bool:
        """Prevent event storms from rapid successive changes."""
        now = time.time()
        last = self._throttle.get(path, 0)
        if now - last < self._throttle_interval:
            return True
        self._throttle[path] = now
        return False

    def on_created(self, event):
        if event.is_directory or self._should_exclude(event.src_path):
            return
        if self._throttled(event.src_path):
            return

        file_hash = sha256_file(event.src_path)
        file_size = _safe_file_size(event.src_path)

        self.baseline.update(event.src_path, file_hash)

        self.bus.publish(Event(
            category=EventCategory.FILE_CREATE,
            severity=Severity.INFO,
            source="fim",
            data={
                "path": event.src_path,
                "hash": file_hash,
                "size": file_size,
                "action": "created",
            },
        ))
        logger.debug(f"FILE_CREATE: {event.src_path}")

    def on_modified(self, event):
        if event.is_directory or self._should_exclude(event.src_path):
            return
        if self._throttled(event.src_path):
            return

        new_hash = sha256_file(event.src_path)
        old_hash = self.baseline.get_hash(event.src_path)
        file_size = _safe_file_size(event.src_path)

        # Only alert if hash actually changed (watchdog can fire on metadata-only changes)
        if new_hash and old_hash and new_hash == old_hash:
            return

        severity = Severity.INFO
        # Modifications to system paths are higher severity
        system_prefixes = ["/etc", "/usr/bin", "/usr/sbin", "/usr/lib",
                           r"C:\Windows", r"C:\Program Files"]
        if any(event.src_path.startswith(p) for p in system_prefixes):
            severity = Severity.HIGH

        self.baseline.update(event.src_path, new_hash)

        self.bus.publish(Event(
            category=EventCategory.FILE_MODIFY,
            severity=severity,
            source="fim",
            data={
                "path": event.src_path,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "size": file_size,
                "action": "modified",
            },
            mitre_attack="T1565.001" if severity == Severity.HIGH else "",
        ))
        logger.debug(f"FILE_MODIFY: {event.src_path} ({old_hash[:8] if old_hash else '?'}→{new_hash[:8] if new_hash else '?'})")

    def on_deleted(self, event):
        if event.is_directory or self._should_exclude(event.src_path):
            return

        old_hash = self.baseline.get_hash(event.src_path)
        self.baseline.remove(event.src_path)

        self.bus.publish(Event(
            category=EventCategory.FILE_DELETE,
            severity=Severity.LOW,
            source="fim",
            data={
                "path": event.src_path,
                "old_hash": old_hash,
                "action": "deleted",
            },
        ))

    def on_moved(self, event):
        if event.is_directory or self._should_exclude(event.src_path):
            return

        file_hash = sha256_file(event.dest_path)
        self.baseline.remove(event.src_path)
        self.baseline.update(event.dest_path, file_hash)

        self.bus.publish(Event(
            category=EventCategory.FILE_MOVE,
            severity=Severity.LOW,
            source="fim",
            data={
                "src_path": event.src_path,
                "dest_path": event.dest_path,
                "hash": file_hash,
                "action": "moved",
            },
        ))


def _safe_file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except (OSError, FileNotFoundError):
        return -1


class BaselineDB:
    """
    SQLite-backed file hash baseline.
    Stores SHA-256 hashes for all monitored files to detect modifications.
    """

    def __init__(self, db_path: str = "data/baseline.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                path TEXT PRIMARY KEY,
                hash TEXT,
                size INTEGER,
                mtime REAL,
                scanned_at REAL
            )
        """)
        self._conn.commit()

    def update(self, path: str, file_hash: str | None):
        try:
            mtime = os.path.getmtime(path)
            size = os.path.getsize(path)
        except (OSError, FileNotFoundError):
            mtime = 0
            size = 0

        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO baselines
                   (path, hash, size, mtime, scanned_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (path, file_hash, size, mtime, time.time()),
            )
            self._conn.commit()

    def get_hash(self, path: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT hash FROM baselines WHERE path = ?", (path,)
            ).fetchone()
            return row[0] if row else None

    def remove(self, path: str):
        with self._lock:
            self._conn.execute("DELETE FROM baselines WHERE path = ?", (path,))
            self._conn.commit()

    def close(self):
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def build_baseline(self, watch_paths: list[str], exclude_patterns: list[str] | None = None):
        """Walk all watched directories and hash every file."""
        exclude = exclude_patterns or []
        count = 0
        for watch_path in watch_paths:
            p = Path(watch_path)
            if not p.exists():
                logger.warning(f"Watch path does not exist: {watch_path}")
                continue

            if p.is_file():
                h = sha256_file(str(p))
                self.update(str(p), h)
                count += 1
                continue

            for root, dirs, files in os.walk(watch_path):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if not any(ex in d for ex in exclude)]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if any(ex in fpath for ex in exclude):
                        continue
                    h = sha256_file(fpath)
                    if h:
                        self.update(fpath, h)
                        count += 1
        logger.info(f"Baseline built: {count} files hashed")
        return count


class FileIntegrityMonitor:
    """
    Main FIM orchestrator. Creates watchdog observers for all configured paths.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self.baseline = BaselineDB(
            db_path=config.get("baseline_db", "data/baseline.db")
        )
        self.handler = FIMHandler(
            event_bus=event_bus,
            baseline_db=self.baseline,
            exclude_patterns=config.get("exclude_patterns", []),
        )
        self.observer = Observer()
        self._running = False

    def start(self):
        """Start the FIM: baseline + real-time monitoring."""
        watch_paths = self.config.get("watch_paths", [])
        exclude = self.config.get("exclude_patterns", [])

        # Build initial baseline
        if self.config.get("baseline_on_start", True):
            logger.info("Building file integrity baseline...")
            count = self.baseline.build_baseline(watch_paths, exclude)
            logger.info(f"Baseline complete: {count} files")

        # Schedule watchers
        for path in watch_paths:
            if Path(path).exists():
                self.observer.schedule(self.handler, path, recursive=True)
                logger.info(f"FIM watching: {path}")
            else:
                logger.warning(f"FIM path does not exist, skipping: {path}")

        self.observer.start()
        self._running = True

        self.bus.publish(Event(
            category=EventCategory.SYSTEM_START,
            severity=Severity.INFO,
            source="fim",
            data={"watch_paths": watch_paths, "status": "started"},
        ))

    def stop(self):
        """Stop FIM gracefully."""
        if self._running:
            self.observer.stop()
            self.observer.join(timeout=5)
            self._running = False
            logger.info("FIM stopped")

    @property
    def is_running(self) -> bool:
        return self._running
