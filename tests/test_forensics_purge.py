"""
AEGIS — Forensics Rotation Test
================================
Production audit found data/forensics growing at ~340 MB/day (11k
snapshots / 2.2 GB in 6.5 days) with no rotation. `purge_forensics`
deletes snapshot_*.json older than retention; `purge_expired_all`
runs it alongside the quarantine purge so a single cron entry rotates
both. Cases still in quarantine are protected because `purge_case`
relies on snapshot existence as its evidence gate.

Invariants:
  1. Old, unprotected snapshot is deleted.
  2. Recent snapshot (newer than cutoff) is kept.
  3. Old snapshot whose case_id is in the quarantine protection set
     is KEPT — evidence gate must not be undermined.
  4. Non-snapshot files in forensics_dir (baselines, notes) are
     left alone.
  5. Snapshot whose JSON is malformed AND filename doesn't fit the
     `snapshot_<epoch>_<case_id>.json` convention is reported as
     an error rather than crashing.
  6. ResponseEngine.purge_expired emits a `forensics_rotated` event
     when forensics retention is configured.
  7. Setting forensics_retention_days=0 disables rotation entirely.
"""
import os
import sys
import json
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.response import ResponseEngine
from aegis.response.purge import (
    purge_forensics,
    purge_expired_all,
    _case_ids_from_quarantine,
    _parse_case_id_from_snapshot,
)


PASS = "[PASS]"
FAIL = "[FAIL]"
failures: list[str] = []


def check(cond: bool, label: str, detail: str = ""):
    if cond:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label} — {detail}")
        failures.append(label)


def section(title: str):
    print(f"\n=== {title} ===")


def _write_snapshot(path: Path, case_id: str, mtime_offset_s: float):
    payload = {
        "trigger_event": {
            "data": {"case_id": case_id, "rule_id": "test_rule"},
        },
        "captured_at": time.time() + mtime_offset_s,
    }
    path.write_text(json.dumps(payload))
    target = time.time() + mtime_offset_s
    os.utime(path, (target, target))


def _write_quarantine_meta(qdir: Path, case_id: str):
    qdir.mkdir(parents=True, exist_ok=True)
    meta = qdir / f"1000_{case_id}_aaaa_payload.bin.meta.json"
    meta.write_text(json.dumps({
        "case_id": case_id,
        "state": "STAGED",
        "quarantined_at": time.time(),
    }))


def test_filename_parser():
    section("1. _parse_case_id_from_snapshot helper")
    p = Path("snapshot_1700000000_abcdef123456.json")
    check(_parse_case_id_from_snapshot(p) == "abcdef123456",
          "parses snapshot_<epoch>_<case_id>.json")
    check(_parse_case_id_from_snapshot(Path("hardening_baseline.json")) is None,
          "ignores non-snapshot filenames")
    check(_parse_case_id_from_snapshot(Path("snapshot_1700000000_.json")) is None,
          "rejects empty case_id")


def test_basic_rotation():
    section("2. purge_forensics: delete old, keep recent, keep protected")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_fpurge_basic_"))
    fdir = tmp / "forensics"
    fdir.mkdir()

    retention_s = 7 * 86400  # 7 days
    now = time.time()

    # Old + unprotected → should be purged
    old_orphan = fdir / "snapshot_100_aaaaaaaaaaaa.json"
    _write_snapshot(old_orphan, "aaaaaaaaaaaa", -10 * 86400)

    # Old + protected (case still in quarantine) → kept
    old_protected = fdir / "snapshot_200_bbbbbbbbbbbb.json"
    _write_snapshot(old_protected, "bbbbbbbbbbbb", -10 * 86400)

    # Recent → kept regardless of protection
    recent = fdir / "snapshot_300_cccccccccccc.json"
    _write_snapshot(recent, "cccccccccccc", -1 * 86400)

    # Non-snapshot file → ignored entirely
    baseline = fdir / "hardening_baseline.json"
    baseline.write_text("{}")
    target = now - 30 * 86400
    os.utime(baseline, (target, target))

    result = purge_forensics(
        fdir, retention_s=retention_s, now=now,
        protected_case_ids={"bbbbbbbbbbbb"},
    )

    check(result["scanned"] == 3,
          f"scanned 3 snapshots (got {result['scanned']})")
    check(result["purged"] == 1, f"purged 1 (got {result['purged']})")
    check(result["skipped_recent"] == 1,
          f"skipped 1 recent (got {result['skipped_recent']})")
    check(result["skipped_protected"] == 1,
          f"skipped 1 protected (got {result['skipped_protected']})")
    check(not old_orphan.exists(), "old orphan snapshot deleted")
    check(old_protected.exists(), "protected snapshot kept")
    check(recent.exists(), "recent snapshot kept")
    check(baseline.exists(), "non-snapshot file untouched")


def test_protection_set_from_quarantine():
    section("3. _case_ids_from_quarantine: builds protection set from metas")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_fpurge_proto_"))
    qdir = tmp / "q"
    _write_quarantine_meta(qdir, "case-alpha")
    _write_quarantine_meta(qdir, "case-beta")

    ids = _case_ids_from_quarantine(qdir)
    check(ids == {"case-alpha", "case-beta"},
          "protection set covers every case still in quarantine",
          f"got {ids}")


def test_combined_purge_runs_both():
    section("4. purge_expired_all: rotates quarantine AND forensics")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_fpurge_combo_"))
    qdir = tmp / "q"
    qdir.mkdir()
    fdir = tmp / "f"
    fdir.mkdir()

    # An old snapshot for a case still in quarantine — must survive.
    _write_quarantine_meta(qdir, "live-case")
    keep = fdir / "snapshot_100_live-case.json"
    _write_snapshot(keep, "live-case", -100 * 86400)

    # An orphaned old snapshot — must die.
    drop = fdir / "snapshot_200_dead-case.json"
    _write_snapshot(drop, "dead-case", -100 * 86400)

    out = purge_expired_all(
        qdir,
        retention_s=30 * 86400,
        forensics_dir=fdir,
        forensics_retention_s=7 * 86400,
        require_forensic=False,
        secure_overwrite=False,
    )
    check("forensics" in out, "combined result includes forensics block")
    check(out["forensics"]["purged"] == 1, "1 orphan snapshot purged")
    check(out["forensics"]["skipped_protected"] == 1,
          "1 live-case snapshot kept by protection set")
    check(keep.exists(), "live-case snapshot still on disk")
    check(not drop.exists(), "dead-case snapshot deleted")


def test_disabled_when_zero():
    section("5. forensics_retention_s=0 disables forensics rotation")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_fpurge_off_"))
    qdir = tmp / "q"
    qdir.mkdir()
    fdir = tmp / "f"
    fdir.mkdir()

    snap = fdir / "snapshot_100_x.json"
    _write_snapshot(snap, "x", -1000 * 86400)

    out = purge_expired_all(
        qdir,
        retention_s=30 * 86400,
        forensics_dir=fdir,
        forensics_retention_s=0,
        require_forensic=False,
        secure_overwrite=False,
    )
    check("forensics" not in out,
          "result has NO forensics key when retention is 0")
    check(snap.exists(), "ancient snapshot kept (rotation disabled)")


def test_engine_publishes_event():
    section("6. ResponseEngine.purge_expired emits forensics_rotated event")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_fpurge_engine_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    engine = ResponseEngine(bus, {
        "auto_respond": True,
        "quarantine_dir": str(tmp / "q"),
        "forensics_dir": str(tmp / "f"),
        "severity_actions": {},
        "hash_sweep": {"enabled": False},
        "persistence_hunt": {"enabled": False},
        "hardening_recheck": {"enabled": False},
        "purge": {"retention_days": 30, "require_forensic": False,
                  "secure_overwrite": False},
        "forensics": {"retention_days": 7},
    })

    # Plant an orphaned old snapshot the engine should rotate.
    snap = engine.forensics_dir / "snapshot_100_orphan.json"
    _write_snapshot(snap, "orphan", -100 * 86400)

    captured: list[Event] = []
    bus.subscribe("response.purge", lambda e: captured.append(e))

    result = engine.purge_expired(operator="test")
    time.sleep(0.05)

    check(not snap.exists(), "engine rotated the orphan snapshot")
    rotated = [e for e in captured
               if e.data.get("action") == "forensics_rotated"]
    check(len(rotated) == 1,
          f"forensics_rotated event published once (got {len(rotated)})")
    if rotated:
        ev = rotated[0]
        check(ev.data.get("purged") == 1,
              "event reports purged=1",
              f"data={ev.data}")
        check(ev.data.get("retention_s") == 7 * 86400,
              "event carries retention_s")
    check("forensics" in result.get("summary", {}),
          "summary block includes forensics rollup",
          f"summary={result.get('summary')}")


def main():
    print("=" * 60)
    print("AEGIS — Forensics Rotation Test")
    print("=" * 60)

    test_filename_parser()
    test_basic_rotation()
    test_protection_set_from_quarantine()
    test_combined_purge_runs_both()
    test_disabled_when_zero()
    test_engine_publishes_event()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
