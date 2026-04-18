"""
AEGIS Core Event Bus
====================
Central pub/sub event system. Every module publishes and subscribes to typed events.
This is the nervous system — all telemetry, detections, and responses flow through here.

Design decisions:
  - Thread-safe: monitors run in their own threads
  - Typed events: every event has a category, severity, and structured data
  - Persistent: events written to SQLite for forensics and replay
  - Bounded: ring buffer prevents memory exhaustion from event storms
"""

import time
import uuid
import json
import sqlite3
import hashlib
import threading
import logging
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Callable, Any
from collections import deque
from pathlib import Path

logger = logging.getLogger("aegis.core.events")


class EventCategory(str, Enum):
    """Event categories matching our architecture layers."""
    # Monitoring events (Layer 1)
    FILE_CREATE = "file.create"
    FILE_MODIFY = "file.modify"
    FILE_DELETE = "file.delete"
    FILE_MOVE = "file.move"
    PROC_CREATE = "proc.create"
    PROC_EXIT = "proc.exit"
    PROC_SUSPICIOUS = "proc.suspicious"
    NET_CONNECT = "net.connect"
    NET_LISTEN = "net.listen"
    NET_CLOSE = "net.close"
    RESOURCE_CPU = "resource.cpu"
    RESOURCE_MEMORY = "resource.memory"
    RESOURCE_DISK = "resource.disk"

    # Detection events (Layer 2)
    DETECTION_YARA = "detection.yara"
    DETECTION_BEHAVIORAL = "detection.behavioral"
    DETECTION_ANOMALY = "detection.anomaly"
    DETECTION_SUPPLY_CHAIN = "detection.supply_chain"

    # Response events (Layer 4)
    RESPONSE_KILL = "response.kill"
    RESPONSE_QUARANTINE = "response.quarantine"
    RESPONSE_ALERT = "response.alert"
    RESPONSE_FORENSIC = "response.forensic"

    # System events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_ERROR = "system.error"
    SYSTEM_HEALTH = "system.health"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Event:
    """A single AEGIS event. Immutable after creation."""
    category: EventCategory
    severity: Severity
    source: str                          # Module that generated this event
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    mitre_attack: str = ""               # MITRE ATT&CK technique ID
    hostname: str = ""                   # For multi-host correlation

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        d["category"] = EventCategory(d["category"])
        d["severity"] = Severity(d["severity"])
        return cls(**d)


# Type alias for subscriber callbacks
Subscriber = Callable[[Event], None]


class EventBus:
    """
    Thread-safe publish/subscribe event bus.

    Usage:
        bus = EventBus()
        bus.subscribe("detection.*", my_handler)
        bus.publish(Event(category=EventCategory.DETECTION_YARA, ...))
    """

    def __init__(self, max_buffer: int = 10000, db_path: str | None = None):
        self._subscribers: dict[str, list[Subscriber]] = {}
        self._lock = threading.RLock()
        self._buffer: deque[Event] = deque(maxlen=max_buffer)
        self._event_count = 0
        self._db_path = db_path
        self._db_conn: sqlite3.Connection | None = None
        self._running = False

        if db_path:
            self._init_db(db_path)

    def _init_db(self, db_path: str):
        """Initialize SQLite event store for persistence and forensics."""
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_conn = sqlite3.connect(db_path, check_same_thread=False)
        self._db_lock = threading.Lock()
        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                seq INTEGER,
                timestamp REAL,
                category TEXT,
                severity TEXT,
                source TEXT,
                mitre_attack TEXT,
                hostname TEXT,
                data TEXT,
                prev_hash TEXT,
                chain_hash TEXT
            )
        """)
        # Migrate older databases that pre-date the hash-chain columns.
        existing_cols = {r[1] for r in self._db_conn.execute(
            "PRAGMA table_info(events)").fetchall()}
        for col, ddl in (("seq", "INTEGER"), ("prev_hash", "TEXT"),
                         ("chain_hash", "TEXT"),
                         # Triage state — operator metadata, NOT part of the
                         # hash-chain payload, so updates don't break verify_chain().
                         ("ack_state", "TEXT"),
                         ("ack_at", "REAL"),
                         ("ack_by", "TEXT")):
            if col not in existing_cols:
                self._db_conn.execute(f"ALTER TABLE events ADD COLUMN {col} {ddl}")
        # Recover the chain head from disk so a restart continues the chain.
        cur = self._db_conn.execute(
            "SELECT seq, chain_hash FROM events WHERE seq IS NOT NULL "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self._chain_seq = (cur[0] or 0) if cur else 0
        self._chain_prev = (cur[1] or "") if cur else ""
        self._db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_category
            ON events(category)
        """)
        self._db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_severity
            ON events(severity)
        """)
        self._db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
        """)
        self._db_conn.commit()
        logger.info(f"Event store initialized at {db_path}")

    def subscribe(self, pattern: str, callback: Subscriber):
        """
        Subscribe to events matching a pattern.

        Patterns:
            "detection.yara"   — exact match
            "detection.*"      — all detection events
            "*"                — all events
        """
        with self._lock:
            if pattern not in self._subscribers:
                self._subscribers[pattern] = []
            self._subscribers[pattern].append(callback)
            logger.debug(f"Subscriber registered for pattern: {pattern}")

    def unsubscribe(self, pattern: str, callback: Subscriber):
        """Remove a subscriber."""
        with self._lock:
            if pattern in self._subscribers:
                self._subscribers[pattern] = [
                    s for s in self._subscribers[pattern] if s != callback
                ]

    def publish(self, event: Event):
        """
        Publish an event to all matching subscribers.
        Also persists to SQLite if configured.
        """
        self._event_count += 1
        self._buffer.append(event)

        # Persist to database
        if self._db_conn:
            self._persist_event(event)

        # Find and notify matching subscribers
        with self._lock:
            subscribers = list(self._subscribers.items())

        for pattern, callbacks in subscribers:
            if self._matches(pattern, event.category.value):
                for callback in callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(
                            f"Subscriber error for {pattern}: {e}",
                            exc_info=True
                        )

    def _matches(self, pattern: str, category: str) -> bool:
        """Check if an event category matches a subscription pattern."""
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return category.startswith(prefix)
        return pattern == category

    def _persist_event(self, event: Event):
        """Write event to SQLite store. Each row carries a SHA-256 hash chained
        to the previous row's hash — any retroactive edit invalidates every
        downstream row, making post-hoc tampering detectable via verify_chain()."""
        try:
            data_json = json.dumps(event.data, default=str)
            with self._db_lock:
                self._chain_seq += 1
                seq = self._chain_seq
                prev_hash = self._chain_prev
                payload = (
                    f"{seq}|{event.event_id}|{event.timestamp}|"
                    f"{event.category.value}|{event.severity.value}|"
                    f"{event.source}|{event.mitre_attack}|{event.hostname}|"
                    f"{data_json}"
                )
                chain_hash = hashlib.sha256(
                    (prev_hash + "|" + payload).encode("utf-8")
                ).hexdigest()
                self._db_conn.execute(
                    """INSERT OR REPLACE INTO events
                       (event_id, seq, timestamp, category, severity, source,
                        mitre_attack, hostname, data, prev_hash, chain_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.event_id, seq, event.timestamp,
                        event.category.value, event.severity.value,
                        event.source, event.mitre_attack, event.hostname,
                        data_json, prev_hash, chain_hash,
                    ),
                )
                self._db_conn.commit()
                self._chain_prev = chain_hash
        except Exception as e:
            logger.error(f"Failed to persist event: {e}")

    def verify_chain(self) -> tuple[bool, list[dict]]:
        """Walk the events table in seq order, recompute each chain_hash, and
        report any rows where the stored hash disagrees. An empty list means
        the log has not been tampered with since AEGIS last wrote to it."""
        if not self._db_conn:
            return True, []
        problems: list[dict] = []
        with self._db_lock:
            rows = self._db_conn.execute(
                """SELECT seq, event_id, timestamp, category, severity, source,
                          mitre_attack, hostname, data, prev_hash, chain_hash
                   FROM events WHERE seq IS NOT NULL ORDER BY seq ASC"""
            ).fetchall()
        prev = ""
        for r in rows:
            (seq, eid, ts, cat, sev, src, mitre, host, data, stored_prev,
             stored_chain) = r
            if stored_prev != prev:
                problems.append({"seq": seq, "event_id": eid,
                                 "issue": "prev_hash mismatch",
                                 "expected": prev, "stored": stored_prev})
            payload = f"{seq}|{eid}|{ts}|{cat}|{sev}|{src}|{mitre}|{host}|{data}"
            recomputed = hashlib.sha256(
                (stored_prev + "|" + payload).encode("utf-8")
            ).hexdigest()
            if recomputed != stored_chain:
                problems.append({"seq": seq, "event_id": eid,
                                 "issue": "chain_hash mismatch",
                                 "expected": recomputed, "stored": stored_chain})
            prev = stored_chain
        return (not problems), problems

    def query_events(
        self,
        category: str | None = None,
        severity: str | None = None,
        since: float | None = None,
        limit: int = 100,
        ack_state: str | None = None,
    ) -> list[dict]:
        """Query persisted events for forensics and analysis.

        ack_state: filter by triage state — 'open' (NULL), 'ack', 'dismissed',
                   or None (no filter).
        """
        if not self._db_conn:
            return []

        query = "SELECT * FROM events WHERE 1=1"
        params = []

        if category:
            query += " AND category LIKE ?"
            params.append(category.replace("*", "%"))
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        if ack_state == "open":
            query += " AND ack_state IS NULL"
        elif ack_state in ("ack", "dismissed"):
            query += " AND ack_state = ?"
            params.append(ack_state)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._db_lock:
            cursor = self._db_conn.execute(query, params)
            columns = [d[0] for d in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def set_ack_state(self, event_ids: list[str], state: str,
                      operator: str = "web") -> int:
        """Mark events as 'ack' or 'dismissed'. Returns rows updated.

        Triage metadata lives outside the hash-chained payload, so updates
        here do NOT invalidate verify_chain().
        """
        if not self._db_conn or not event_ids:
            return 0
        if state not in ("ack", "dismissed", "open"):
            raise ValueError(f"invalid ack_state: {state}")
        new_state = None if state == "open" else state
        ts = time.time() if new_state else None
        op = operator if new_state else None
        placeholders = ",".join("?" * len(event_ids))
        with self._db_lock:
            cur = self._db_conn.execute(
                f"UPDATE events SET ack_state=?, ack_at=?, ack_by=? "
                f"WHERE event_id IN ({placeholders})",
                [new_state, ts, op, *event_ids],
            )
            self._db_conn.commit()
            return cur.rowcount

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def recent_events(self) -> list[Event]:
        return list(self._buffer)

    def shutdown(self):
        """Clean shutdown."""
        if self._db_conn:
            self._db_conn.close()
        logger.info(f"Event bus shut down. Total events processed: {self._event_count}")
