"""
AEGIS Chain — Process-Safety Regression Test
=============================================
Reproduces the split-brain bug that corrupted production data/events.db:
two writers attached to the same DB file, each caching its own _chain_seq
from disk, racing inserts and forking the chain. With the BEGIN IMMEDIATE
fix in place, the chain stays linear under concurrent writers.

Invariants verified:
  1. Multi-thread writers in one process: chain still verifies.
  2. Multi-process writers in two processes: chain still verifies.
  3. seq is dense (no gaps, no duplicates).
  4. Duplicate event_id is refused without poisoning the chain.
"""
import os
import sys
import json
import time
import sqlite3
import tempfile
import threading
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity


PASS = "[PASS]"
FAIL = "[FAIL]"
failures: list[str] = []


def check(cond: bool, label: str, detail: str = ""):
    if cond:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label} - {detail}")
        failures.append(label)


def section(title: str):
    print(f"\n=== {title} ===")


def _publish_n(bus: EventBus, n: int, source: str):
    for i in range(n):
        bus.publish(Event(
            category=EventCategory.SYSTEM_HEALTH,
            severity=Severity.INFO,
            source=source,
            data={"i": i},
        ))


def test_thread_concurrency():
    """Many threads, one process — proves _db_lock + BEGIN IMMEDIATE
    serialise within a process."""
    section("1. Multi-thread writers (single process)")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_chain_thread_"))
    bus = EventBus(db_path=str(tmp / "events.db"))

    threads = []
    per_thread = 200
    n_threads = 8
    for t in range(n_threads):
        threads.append(threading.Thread(
            target=_publish_n, args=(bus, per_thread, f"t{t}")))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok, problems = bus.verify_chain()
    check(ok, "chain verifies after concurrent thread writers",
          f"problems={problems[:3]}")
    rows = bus._db_conn.execute(
        "SELECT COUNT(*), MAX(seq), MIN(seq) FROM events"
    ).fetchone()
    expected = n_threads * per_thread
    check(rows[0] == expected,
          f"row count == {expected}", f"got {rows[0]}")
    check(rows[1] == expected and rows[2] == 1,
          f"seq is dense [1..{expected}]",
          f"min={rows[2]} max={rows[1]}")
    bus.shutdown()


def _child_writer_script(db_path: str, tag: str, n: int) -> str:
    """Standalone Python that opens its OWN bus on the SAME db file."""
    return f"""
import sys
sys.path.insert(0, {repr(str(Path(__file__).resolve().parent.parent))})
from aegis.core import EventBus, Event, EventCategory, Severity
bus = EventBus(db_path={db_path!r})
for i in range({n}):
    bus.publish(Event(
        category=EventCategory.SYSTEM_HEALTH,
        severity=Severity.INFO,
        source={tag!r},
        data={{"i": i, "tag": {tag!r}}},
    ))
bus.shutdown()
"""


def test_process_concurrency():
    """Two OS processes attached to the same DB — proves BEGIN IMMEDIATE
    plus PRAGMA busy_timeout serialise across processes."""
    section("2. Multi-process writers (the original split-brain scenario)")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_chain_proc_"))
    db = tmp / "events.db"
    # Pre-create the schema by opening + closing once.
    EventBus(db_path=str(db)).shutdown()

    n_each = 150
    p1 = subprocess.Popen(
        [sys.executable, "-c", _child_writer_script(str(db), "proc1", n_each)],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    p2 = subprocess.Popen(
        [sys.executable, "-c", _child_writer_script(str(db), "proc2", n_each)],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    rc1 = p1.wait(timeout=60)
    rc2 = p2.wait(timeout=60)
    check(rc1 == 0 and rc2 == 0,
          "both writer processes exited cleanly",
          f"rc1={rc1} rc2={rc2}")

    # Reopen in this process to verify.
    bus = EventBus(db_path=str(db))
    ok, problems = bus.verify_chain()
    check(ok, "chain verifies across two-process concurrent writers",
          f"problems={problems[:3]}")

    rows = bus._db_conn.execute(
        "SELECT COUNT(*), MAX(seq), MIN(seq) FROM events"
    ).fetchone()
    total, mx, mn = rows
    check(total == 2 * n_each,
          f"row count == {2 * n_each}", f"got {total}")
    check(mx == total and mn == 1,
          f"seq is dense [1..{total}]", f"min={mn} max={mx}")

    proc1_count = bus._db_conn.execute(
        "SELECT COUNT(*) FROM events WHERE source='proc1'").fetchone()[0]
    proc2_count = bus._db_conn.execute(
        "SELECT COUNT(*) FROM events WHERE source='proc2'").fetchone()[0]
    check(proc1_count == n_each and proc2_count == n_each,
          "both processes wrote their full quota",
          f"proc1={proc1_count} proc2={proc2_count}")
    bus.shutdown()


def test_duplicate_event_id_refused():
    """A duplicate event_id must NOT overwrite the chained row."""
    section("3. Duplicate event_id ignored, chain preserved")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_chain_dup_"))
    bus = EventBus(db_path=str(tmp / "events.db"))

    e = Event(
        category=EventCategory.SYSTEM_HEALTH,
        severity=Severity.INFO,
        source="dup_test",
        data={"k": 1},
    )
    bus.publish(e)
    # Mutate data and re-publish with same event_id — must NOT overwrite.
    e.data["k"] = 999
    bus.publish(e)

    rows = bus._db_conn.execute(
        "SELECT COUNT(*) FROM events WHERE event_id=?", (e.event_id,)
    ).fetchall()
    check(rows[0][0] == 1,
          "duplicate event_id stored exactly once",
          f"got {rows[0][0]}")

    stored = bus._db_conn.execute(
        "SELECT data FROM events WHERE event_id=?", (e.event_id,)
    ).fetchone()
    parsed = json.loads(stored[0])
    check(parsed["k"] == 1,
          "original payload preserved (not overwritten by duplicate)",
          f"got k={parsed['k']}")

    ok, problems = bus.verify_chain()
    check(ok, "chain still verifies after duplicate publish attempt",
          f"problems={problems[:3]}")
    bus.shutdown()


def main():
    print("=" * 60)
    print("AEGIS CHAIN - PROCESS-SAFETY REGRESSION TEST")
    print("=" * 60)
    test_thread_concurrency()
    test_process_concurrency()
    test_duplicate_event_id_refused()
    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
