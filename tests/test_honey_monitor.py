"""
AEGIS — Honeytoken Monitor Test
================================
Verifies the canary-planting + tamper-detection pipeline that lights
up on ransomware encryption walks and credential-grep behaviour.

Invariants:
  1. Plant: missing canary is created, sha256/size/sentinel recorded,
     baseline file persisted, an INFO `canary_planted` event fires.
  2. Plant idempotency: a second start does NOT re-plant or re-write
     a canary that's already in the baseline.
  3. Sacred-data guard: an existing operator file at the canary path
     is left UNTOUCHED and not added to the baseline.
  4. Modification detection: editing a canary's content fires HIGH
     `canary_modified` with the old + new sha256 and a sentinel
     presence flag.
  5. Sentinel rewrite detection: even if the new sha matches the old
     length, a body that drops the sentinel is reported as
     `sentinel_present=False`.
  6. Deletion detection: rm of a canary fires HIGH `canary_deleted`.
  7. Auto-replant: with `auto_replant=true` a deleted canary is
     restored on the next pass and a `canary_replanted` audit fires.
  8. Operator extras: an `extra_canaries` config entry is planted
     alongside the defaults.
  9. MITRE + source: every honey event carries source="honey",
     mitre_attack="T1083", category=DETECTION_HONEYTOKEN.
"""
import os
import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.monitors.honey_mon import (
    HoneytokenMonitor,
    _render,
    _TEMPLATES,
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


def _make_monitor(tmp: Path, **extra_cfg) -> tuple[EventBus, HoneytokenMonitor, list[Event]]:
    """Build a monitor with plant_user_dirs disabled — tests provide
    canaries via `extra_canaries` so they don't pollute the actual
    user profile during the run."""
    bus = EventBus(db_path=str(tmp / "events.db"))
    cfg = {
        "enabled": True,
        "poll_interval_seconds": 60,
        "plant_on_start": False,           # tests trigger planting explicitly
        "plant_user_dirs": False,
        "auto_replant": False,
        "baseline_path": str(tmp / "honey.baseline.json"),
        "extra_canaries": [],
    }
    cfg.update(extra_cfg)
    mon = HoneytokenMonitor(bus, cfg)
    captured: list[Event] = []
    bus.subscribe("detection.honeytoken", lambda e: captured.append(e))
    return bus, mon, captured


def test_render_includes_sentinel():
    section("0. _render: every template embeds the sentinel")
    for name in _TEMPLATES:
        body = _render(name, "AEGIS-HONEY-CANARY-deadbeef")
        check(b"AEGIS-HONEY-CANARY-deadbeef" in body,
              f"template '{name}' embeds sentinel")
        check(len(body) > 32, f"template '{name}' is non-trivial")


def test_plant_basic():
    section("1. Plant: writes canary, records baseline, audit fires")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_plant_"))
    target = tmp / "creds" / "passwords.txt"
    bus, mon, captured = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "passwords"},
    ])

    mon._plant_missing()

    check(target.exists(), "canary file created on disk")
    body = target.read_bytes()
    sha = __import__("hashlib").sha256(body).hexdigest()

    entry = mon._baseline.get(str(target))
    check(entry is not None, "baseline entry recorded")
    if entry:
        check(entry["sha256"] == sha, "baseline sha matches file content")
        check(entry["size"] == len(body), "baseline size matches file length")
        check(entry["sentinel"].encode() in body,
              "sentinel is present in canary body")
        check(entry["template"] == "passwords", "template name recorded")

    check(mon.baseline_path.exists(),
          "baseline manifest persisted to disk")

    audits = [e for e in captured
              if e.data.get("action") == "canary_planted"]
    check(len(audits) == 1, f"one canary_planted audit (got {len(audits)})")
    if audits:
        ev = audits[0]
        check(ev.severity == Severity.INFO,
              "audit event severity is INFO")
        check(ev.category == EventCategory.DETECTION_HONEYTOKEN,
              "audit category is DETECTION_HONEYTOKEN")
        check(ev.source == "honey", "audit source is 'honey'")


def test_plant_idempotent():
    section("2. Plant idempotency: second pass does not re-plant")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_idemp_"))
    target = tmp / "passwords.txt"
    bus, mon, captured = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "passwords"},
    ])

    mon._plant_missing()
    first_body = target.read_bytes()
    captured.clear()

    mon._plant_missing()
    second_body = target.read_bytes()

    check(first_body == second_body,
          "canary body unchanged across two plant calls")
    check(not [e for e in captured
               if e.data.get("action") == "canary_planted"],
          "no canary_planted event on second pass")


def test_plant_does_not_overwrite_existing():
    section("3. Sacred-data guard: existing file at canary path is preserved")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_existing_"))
    target = tmp / "Documents" / "passwords.txt"
    target.parent.mkdir(parents=True)
    user_payload = b"OPERATOR_REAL_DATA_DO_NOT_TOUCH"
    target.write_bytes(user_payload)

    bus, mon, captured = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "passwords"},
    ])
    mon._plant_missing()

    check(target.read_bytes() == user_payload,
          "operator file body left untouched")
    check(str(target) not in mon._baseline,
          "skipped path NOT added to baseline")


def test_modification_detected():
    section("4. Modification: tampering fires canary_modified HIGH")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_mod_"))
    target = tmp / "wallet.dat"
    bus, mon, captured = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "wallet"},
    ])
    mon._plant_missing()
    captured.clear()

    # Simulate ransomware: append junk so the hash changes.
    with open(target, "ab") as f:
        f.write(b"\x00" * 256)

    events = mon.check_once()

    check(len(events) == 1, f"one detection event (got {len(events)})")
    if events:
        ch = events[0]
        check(ch["action"] == "canary_modified",
              f"action == canary_modified (got {ch['action']})")
        check(ch["expected_sha256"] != ch["actual_sha256"],
              "hashes differ")
        check(ch["sentinel_present"] is True,
              "sentinel still present after append")

    high = [e for e in captured
            if e.data.get("action") == "canary_modified"]
    check(len(high) == 1, "exactly one canary_modified event published")
    if high:
        ev = high[0]
        check(ev.severity == Severity.HIGH, "severity is HIGH")
        check(ev.mitre_attack == "T1083", "MITRE T1083 stamped")
        check(ev.data.get("rule_id") == "HONEY-CANARY_MODIFIED",
              "rule_id reflects action")


def test_sentinel_rewrite_detected():
    section("5. Sentinel rewrite: complete content swap is flagged")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_rewrite_"))
    target = tmp / "creds.txt"
    bus, mon, captured = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "passwords"},
    ])
    mon._plant_missing()
    captured.clear()

    # Wholesale rewrite — no sentinel marker survives.
    target.write_bytes(b"completely different content, no marker")

    events = mon.check_once()
    check(len(events) == 1, "one event")
    if events:
        check(events[0]["sentinel_present"] is False,
              "sentinel_present == False after rewrite")


def test_deletion_detected():
    section("6. Deletion fires canary_deleted HIGH")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_del_"))
    target = tmp / "id_rsa.bak"
    bus, mon, captured = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "ssh_key"},
    ])
    mon._plant_missing()
    captured.clear()

    target.unlink()
    events = mon.check_once()

    check(len(events) == 1, "one event")
    if events:
        check(events[0]["action"] == "canary_deleted",
              "action == canary_deleted")

    high = [e for e in captured
            if e.data.get("action") == "canary_deleted"]
    check(len(high) == 1, "one canary_deleted event published")
    if high:
        check(high[0].severity == Severity.HIGH, "severity is HIGH")


def test_auto_replant():
    section("7. auto_replant: deleted canary is restored on next pass")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_replant_"))
    target = tmp / "wallet.dat"
    bus, mon, captured = _make_monitor(tmp,
        auto_replant=True,
        extra_canaries=[{"path": str(target), "template": "wallet"}],
    )
    mon._plant_missing()
    original_sha = mon._baseline[str(target)]["sha256"]
    captured.clear()

    target.unlink()
    mon.check_once()

    check(target.exists(), "canary restored on disk")
    new_sha = mon._baseline[str(target)]["sha256"]
    check(new_sha != original_sha,
          "replanted canary has fresh content (different sha)")

    replants = [e for e in captured
                if e.data.get("action") == "canary_replanted"]
    check(len(replants) == 1,
          f"one canary_replanted audit (got {len(replants)})")


def test_baseline_persists_across_starts():
    section("8. Baseline survives a stop+start cycle")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_persist_"))
    target = tmp / "Documents" / "passwords.txt"

    bus, mon1, _ = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "passwords"},
    ])
    mon1._plant_missing()
    sha1 = mon1._baseline[str(target)]["sha256"]

    bus2, mon2, captured2 = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "passwords"},
    ])
    mon2._load_baseline()
    check(str(target) in mon2._baseline,
          "second monitor loaded baseline from disk")
    check(mon2._baseline[str(target)]["sha256"] == sha1,
          "sha matches the originally-planted hash")

    # Untouched canary — clean check should produce no events.
    events = mon2.check_once()
    check(events == [], "intact canary produces zero events")


def test_unknown_template_skipped():
    section("9. Unknown extra_canaries template is rejected, not crashed")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_honey_badtpl_"))
    target = tmp / "x"
    bus, mon, captured = _make_monitor(tmp, extra_canaries=[
        {"path": str(target), "template": "this_template_does_not_exist"},
    ])
    mon._plant_missing()

    check(not target.exists(),
          "no file planted for unknown template")
    check(str(target) not in mon._baseline,
          "no baseline entry for unknown template")


def main():
    print("=" * 60)
    print("AEGIS — Honeytoken Monitor Test")
    print("=" * 60)

    test_render_includes_sentinel()
    test_plant_basic()
    test_plant_idempotent()
    test_plant_does_not_overwrite_existing()
    test_modification_detected()
    test_sentinel_rewrite_detected()
    test_deletion_detected()
    test_auto_replant()
    test_baseline_persists_across_starts()
    test_unknown_template_skipped()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
