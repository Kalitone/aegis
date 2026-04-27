"""
AEGIS Step 2 — Production-Grade Hash Sweep Test
================================================
What Kaspersky/ESET validate for sibling hunting: given a malicious file
dropped in N locations plus decoys (same size, different content) and
unrelated files, a detection on ONE instance must result in all N
instances quarantined, all decoys untouched, and the primary case must
reference every sibling.

Invariants verified:
  1. Multi-zone sweep: identical-hash siblings across 3 zones all found
  2. Size pre-filter: a same-size-but-different-content decoy is NOT
     quarantined (proves we're hashing, not just name/size matching)
  3. Different-size file is not even hashed (cheap skip)
  4. Quarantine dir is excluded (no re-discovery of our own evidence)
  5. Symlinks are skipped (no out-of-zone reads, no cycles)
  6. Primary meta.json lists every sibling (operator sees full scope)
  7. Each sibling has parent_case_id pointing to the primary
  8. Sweep report is published as an event with accurate counters
  9. Time budget is honored — a budget of 0.001s still returns a dict
 10. Hash sweep disabled via config produces zero sibling events
"""
import os
import sys
import json
import time
import tempfile
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.response import ResponseEngine
from aegis.response.hash_sweep import (
    sweep_for_siblings,
    resolve_default_drop_zones,
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


EVIL_CONTENT = b"EVIL_DROPPER_PAYLOAD_UNIQUE_MARKER_FOR_TEST_" + b"A" * 512
DECOY_SAME_SIZE = b"BENIGN_PLACEHOLDER_DIFFERENT_CONTENT_______" + b"B" * 513
DECOY_DIFFERENT_SIZE = b"TINY"


def test_pure_sweep_function():
    """Unit: sweep function in isolation, no ResponseEngine involved."""
    section("1. sweep_for_siblings: pure function, multi-zone, decoys")

    root = Path(tempfile.mkdtemp(prefix="aegis_step2_pure_"))
    zones = [root / f"zone_{i}" for i in range(3)]
    for z in zones:
        z.mkdir()

    import hashlib
    target_hash = hashlib.sha256(EVIL_CONTENT).hexdigest()
    target_size = len(EVIL_CONTENT)

    # Evil copies in each zone under varied names + nested dirs.
    evil_paths = [
        zones[0] / "evil.bin",
        zones[1] / "sub1" / "sub2" / "evil_copy.dat",
        zones[2] / "evil.exe",
    ]
    for p in evil_paths:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(EVIL_CONTENT)

    # Decoys.
    (zones[0] / "decoy_same_size.bin").write_bytes(DECOY_SAME_SIZE)
    (zones[1] / "decoy_diff_size.bin").write_bytes(DECOY_DIFFERENT_SIZE)
    (zones[2] / "totally_unrelated.txt").write_bytes(b"hello world")

    # Excluded subdir inside a zone (e.g. simulating quarantine dir).
    excluded_dir = zones[0] / "do_not_scan"
    excluded_dir.mkdir()
    (excluded_dir / "also_evil.bin").write_bytes(EVIL_CONTENT)  # SAME hash

    # Symlink: if followed it would duplicate a match; must be skipped.
    if os.name != "nt":  # symlink on posix only for simplicity
        try:
            os.symlink(zones[0], zones[1] / "linked")
        except OSError:
            pass

    report = sweep_for_siblings(
        target_hash=target_hash,
        target_size=target_size,
        drop_zones=zones,
        excluded_paths=[excluded_dir],
        time_budget_s=30.0,
        max_file_size_mb=10,
    )

    match_strs = {str(p) for p in report["matches"]}
    check(len(report["matches"]) == 3,
          "exactly 3 siblings matched",
          f"got {len(report['matches'])}: {sorted(match_strs)}")
    for p in evil_paths:
        check(str(p.resolve()) in match_strs,
              f"match present: {p.name}")
    check(str((excluded_dir / "also_evil.bin").resolve()) not in match_strs,
          "excluded path was NOT scanned",
          f"excluded still matched — exclusion broken")
    check(report["hashed"] >= 3,
          "at least 3 files SHA-256'd (size pre-filter allowed only matches)",
          f"hashed={report['hashed']}")
    # decoy_diff_size is size 4 bytes — must not even be hashed.
    check(report["hashed"] < report["scanned"],
          "size pre-filter eliminated candidates before hashing",
          f"scanned={report['scanned']} hashed={report['hashed']}")
    check(report["budget_exhausted"] is False,
          "budget not exhausted on small tree")
    check(report["elapsed_s"] >= 0,
          "elapsed reported")


def test_tight_budget():
    """A 1ms budget still returns a valid report, not a crash."""
    section("2. Time budget honored — no crash on tiny budget")

    root = Path(tempfile.mkdtemp(prefix="aegis_step2_budget_"))
    for i in range(50):
        (root / f"f_{i}.bin").write_bytes(b"x" * 100)

    report = sweep_for_siblings(
        target_hash="0" * 64,
        target_size=100,
        drop_zones=[root],
        time_budget_s=0.001,
    )
    check(isinstance(report, dict), "tight budget returns dict")
    check("matches" in report, "report has matches key")
    check(report["budget_exhausted"] in (True, False),
          "budget_exhausted is a bool")


def test_end_to_end_multi_zone_quarantine():
    """Full ResponseEngine flow: detection → primary quarantine → sibling
    quarantines → primary meta lists siblings → parent_case_id set."""
    section("3. End-to-end: 3 siblings across zones all quarantined")

    root = Path(tempfile.mkdtemp(prefix="aegis_step2_e2e_"))
    quarantine_dir = root / "quarantine"
    zone_a = root / "zone_a"
    zone_b = root / "zone_b" / "nested"
    zone_c = root / "zone_c"
    for z in (zone_a, zone_b, zone_c):
        z.mkdir(parents=True, exist_ok=True)

    primary = zone_a / "primary_sample.bin"
    sibling1 = zone_b / "renamed_copy.dat"
    sibling2 = zone_c / "third_instance.exe"
    decoy_same_size = zone_b / "looks_suspicious.bin"
    decoy_diff_size = zone_c / "small.bin"

    primary.write_bytes(EVIL_CONTENT)
    sibling1.write_bytes(EVIL_CONTENT)
    sibling2.write_bytes(EVIL_CONTENT)
    decoy_same_size.write_bytes(DECOY_SAME_SIZE)
    decoy_diff_size.write_bytes(DECOY_DIFFERENT_SIZE)

    bus = EventBus(db_path=str(root / "events.db"))
    engine = ResponseEngine(bus, {
        "auto_respond": True,
        "quarantine_dir": str(quarantine_dir),
        "forensics_dir": str(root / "forensics"),
        "severity_actions": {"high": ["quarantine_file"]},
        # Point the sweep only at our test zones — real %TEMP% may contain
        # leftovers from prior runs that would skew counters.
        "hash_sweep": {
            "enabled": True,
            "drop_zones": [str(zone_a.parent), str(zone_b.parent),
                           str(zone_c.parent)],
            "time_budget_s": 30.0,
        },
    })
    engine.start()

    # Capture quarantine + sweep events.
    events: list[Event] = []
    bus.subscribe("response.quarantine", lambda e: events.append(e))

    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        mitre_attack="T1105",
        data={
            "filepath": str(primary),
            "rule_name": "TestDropperFamily",
            "rule_id": "TEST-STEP2-001",
        },
    ))

    time.sleep(0.3)

    # Expect: 1 primary quarantine + 2 sibling quarantines + 1 sweep_complete.
    primary_events = [e for e in events
                      if e.data.get("action") == "file_quarantined"
                      and e.data.get("parent_case_id") is None]
    sibling_events = [e for e in events
                      if e.data.get("action") == "file_quarantined"
                      and e.data.get("parent_case_id")]
    sweep_events = [e for e in events
                    if e.data.get("action") == "hash_sweep_complete"]

    check(len(primary_events) == 1, "exactly one primary quarantine",
          f"got {len(primary_events)}")
    check(len(sibling_events) == 2, "exactly two sibling quarantines",
          f"got {len(sibling_events)}")
    check(len(sweep_events) == 1, "exactly one sweep_complete event",
          f"got {len(sweep_events)}")

    if primary_events and sibling_events:
        parent_id = primary_events[0].data["case_id"]
        for se in sibling_events:
            check(se.data["parent_case_id"] == parent_id,
                  f"sibling case {se.data['case_id']} points to primary",
                  f"got parent_case_id={se.data.get('parent_case_id')}")

    if sweep_events:
        rep = sweep_events[0].data
        check(rep["siblings_found"] == 2,
              "sweep_complete.siblings_found == 2",
              f"got {rep.get('siblings_found')}")
        check(rep["target_sha256"] ==
              __import__('hashlib').sha256(EVIL_CONTENT).hexdigest(),
              "sweep_complete carries target hash")

    # On disk: quarantine dir should now hold 3 files + 3 metas.
    all_q = [p for p in quarantine_dir.iterdir() if p.is_file()]
    binaries = [p for p in all_q if not p.name.endswith(".meta.json")]
    metas = [p for p in all_q if p.name.endswith(".meta.json")]
    check(len(binaries) == 3, "3 binaries in quarantine",
          f"got {len(binaries)}")
    check(len(metas) == 3, "3 metas in quarantine",
          f"got {len(metas)}")

    # Decoys remain in place — not quarantined.
    check(decoy_same_size.exists(),
          "same-size different-content decoy left alone")
    check(decoy_diff_size.exists(),
          "different-size decoy left alone")

    # Primary meta lists siblings.
    primary_meta_path = None
    for m in metas:
        d = json.loads(m.read_text())
        if d.get("parent_case_id") is None:
            primary_meta_path = m
            break
    check(primary_meta_path is not None, "primary meta identifiable")
    if primary_meta_path:
        meta = json.loads(primary_meta_path.read_text())
        sibs = meta.get("siblings") or []
        check(len(sibs) == 2,
              "primary meta.json lists 2 siblings",
              f"got {len(sibs)}")
        origins = {s["original_path"] for s in sibs}
        check(str(sibling1) in origins or str(sibling1.resolve()) in origins,
              "sibling1 present in primary meta",
              f"origins={origins}")
        check(str(sibling2) in origins or str(sibling2.resolve()) in origins,
              "sibling2 present in primary meta",
              f"origins={origins}")

    # All originals moved off disk.
    check(not primary.exists(), "primary original gone from its zone")
    check(not sibling1.exists(), "sibling1 original gone from its zone")
    check(not sibling2.exists(), "sibling2 original gone from its zone")

    engine.stop()
    bus.shutdown()


def test_sweep_disabled():
    """When hash_sweep.enabled=false, siblings are NOT quarantined."""
    section("4. Sweep disabled via config ⇒ no sibling events")

    root = Path(tempfile.mkdtemp(prefix="aegis_step2_off_"))
    quarantine_dir = root / "quarantine"
    zone = root / "zone"
    zone.mkdir()

    primary = zone / "primary.bin"
    sibling = zone / "sibling.bin"
    primary.write_bytes(EVIL_CONTENT)
    sibling.write_bytes(EVIL_CONTENT)

    bus = EventBus(db_path=str(root / "events.db"))
    engine = ResponseEngine(bus, {
        "auto_respond": True,
        "quarantine_dir": str(quarantine_dir),
        "forensics_dir": str(root / "forensics"),
        "severity_actions": {"high": ["quarantine_file"]},
        "hash_sweep": {"enabled": False, "drop_zones": [str(zone)]},
    })
    engine.start()

    events: list[Event] = []
    bus.subscribe("response.quarantine", lambda e: events.append(e))

    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={"filepath": str(primary), "rule_name": "T", "rule_id": "T"},
    ))
    time.sleep(0.2)

    sibling_events = [e for e in events
                      if e.data.get("parent_case_id")]
    sweep_events = [e for e in events
                    if e.data.get("action") == "hash_sweep_complete"]
    check(len(sibling_events) == 0, "no sibling quarantines when disabled",
          f"got {len(sibling_events)}")
    check(len(sweep_events) == 0, "no sweep_complete event when disabled",
          f"got {len(sweep_events)}")
    check(sibling.exists(), "sibling file remains on disk",
          "sibling was quarantined despite disabled sweep")

    engine.stop()
    bus.shutdown()


def test_defaults_resolve():
    """resolve_default_drop_zones returns a non-empty, existing-dir list
    on this host."""
    section("5. Default drop zones resolve")
    zones = resolve_default_drop_zones()
    check(len(zones) >= 1, "at least one default zone resolved",
          f"got {len(zones)}")
    for z in zones:
        check(z.is_dir(), f"zone is a directory: {z}")


if __name__ == "__main__":
    test_pure_sweep_function()
    test_tight_budget()
    test_end_to_end_multi_zone_quarantine()
    test_sweep_disabled()
    test_defaults_resolve()

    print("\n" + "=" * 55)
    if failures:
        print(f"RESULT: {len(failures)} failing check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("RESULT: all Step 2 hash-sweep checks PASSED")
        sys.exit(0)
