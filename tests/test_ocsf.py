"""
AEGIS — OCSF Export Test
=========================
Validates the OCSF v1.1.0 mapping module and the OcsfFileSink that
consumes it. Two reasons we test the mapping in detail:

  1. SIEM ingestion pipelines key on `category_uid` / `class_uid` /
     `type_uid`; a mistype in those is silently dropped by the
     downstream parser.
  2. `type_uid` is mechanically `class_uid * 100 + activity_id` per
     spec — we want a regression catch the day someone "fixes" that.

Invariants:
  1. Every category in EventCategory has a mapping; nothing falls into
     the catch-all triple by accident.
  2. category_uid ∈ {1,2,3,4,5,6} for every entry.
  3. type_uid = class_uid * 100 + activity_id for every output.
  4. Time is emitted in epoch *milliseconds*, not seconds.
  5. AEGIS Severity → OCSF severity_id table is exact (info=1, low=2,
     medium=3, high=4, critical=5).
  6. event_to_ocsf preserves the AEGIS payload under `unmapped`.
  7. MITRE ATT&CK IDs end up in the OCSF `attacks` block when present;
     absent when not.
  8. Convenience `file.path` / `process.pid` lifts work when the input
     event has those data fields.
  9. OcsfFileSink end-to-end: subscribe-to-everything path produces
     valid JSON-lines, one per published event, in the configured file.
 10. OcsfFileSink is silent (no file written) when `enabled: false`.
 11. A KeyError-shaped failure inside the mapper does not propagate
     out of `_on_event`.
"""
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.utils.ocsf import (
    event_to_ocsf,
    mapping_for,
    supported_categories,
    _EVENT_MAP,
    _DEFAULT_TRIPLE,
    _SEVERITY_MAP,
)
from aegis.utils.alerting import OcsfFileSink


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


def _ev(category: EventCategory, severity: Severity = Severity.INFO,
        *, source: str = "test", data: dict | None = None,
        mitre: str = "") -> Event:
    return Event(
        category=category,
        severity=severity,
        source=source,
        data=data or {},
        timestamp=1700000000.123,
        mitre_attack=mitre,
        hostname="testhost",
    )


def test_every_category_mapped():
    section("1. Every EventCategory has an explicit OCSF mapping")
    missing = [c.value for c in EventCategory if c.value not in _EVENT_MAP]
    check(missing == [],
          "no AEGIS category falls back to catch-all by accident",
          f"unmapped: {missing}")


def test_category_uids_are_legal():
    section("2. category_uid ∈ {1..6} for every mapping")
    bad = [(k, t) for k, t in _EVENT_MAP.items() if t[0] not in {1, 2, 3, 4, 5, 6}]
    check(not bad, f"all category_uids legal", f"bad={bad}")


def test_type_uid_formula():
    section("3. type_uid == class_uid * 100 + activity_id (spec contract)")
    for cat in supported_categories():
        ev = _ev(EventCategory(cat))
        out = event_to_ocsf(ev)
        expected = out["class_uid"] * 100 + out["activity_id"]
        check(out["type_uid"] == expected,
              f"type_uid correct for {cat}",
              f"got {out['type_uid']} expected {expected}")


def test_time_is_milliseconds():
    section("4. OCSF `time` is epoch milliseconds, not seconds")
    ev = _ev(EventCategory.DETECTION_YARA)
    out = event_to_ocsf(ev)
    check(out["time"] == 1700000000123,
          f"time == 1700000000123 ms (got {out['time']})")
    check(out["metadata"]["original_time"] == 1700000000.123,
          "metadata.original_time preserves the float seconds value")


def test_severity_table_exact():
    section("5. AEGIS Severity → OCSF severity_id is exact + complete")
    expected = {
        "info": (1, "Informational"),
        "low": (2, "Low"),
        "medium": (3, "Medium"),
        "high": (4, "High"),
        "critical": (5, "Critical"),
    }
    check(_SEVERITY_MAP == expected,
          f"severity table matches spec",
          f"got {_SEVERITY_MAP}")
    for aegis_sev, (ocsf_id, ocsf_name) in expected.items():
        ev = _ev(EventCategory.RESPONSE_ALERT, Severity(aegis_sev))
        out = event_to_ocsf(ev)
        check(out["severity_id"] == ocsf_id,
              f"{aegis_sev} → severity_id={ocsf_id}",
              f"got {out['severity_id']}")
        check(out["severity"] == ocsf_name,
              f"{aegis_sev} → severity name '{ocsf_name}'",
              f"got {out['severity']}")


def test_unmapped_preserves_payload():
    section("6. AEGIS payload survives intact under `unmapped`")
    payload = {"rule_id": "EVIL-1", "rule_name": "evil",
               "filepath": r"C:\Tools\bad.exe", "pid": 4242,
               "score": -0.42}
    ev = _ev(EventCategory.DETECTION_YARA, Severity.HIGH,
             data=payload, source="yara")
    out = event_to_ocsf(ev)

    check(out["unmapped"]["aegis_data"] == payload,
          "data dict preserved verbatim under unmapped.aegis_data")
    check(out["unmapped"]["aegis_category"] == "detection.yara",
          "aegis_category preserved")
    check(out["unmapped"]["aegis_source"] == "yara",
          "aegis_source preserved")
    check(out["unmapped"]["aegis_severity"] == "high",
          "aegis_severity preserved")
    check(out["unmapped"]["aegis_event_id"] == ev.event_id,
          "aegis_event_id preserved")


def test_attacks_block_when_mitre_present():
    section("7. MITRE ATT&CK ID surfaces in OCSF `attacks` block")

    ev = _ev(EventCategory.DETECTION_HONEYTOKEN, Severity.HIGH,
             mitre="T1083")
    out = event_to_ocsf(ev)
    check("attacks" in out, "attacks key present when mitre set")
    if "attacks" in out:
        check(out["attacks"][0]["technique"]["uid"] == "T1083",
              "technique.uid == T1083")

    bare = _ev(EventCategory.DETECTION_HONEYTOKEN, Severity.HIGH)
    out2 = event_to_ocsf(bare)
    check("attacks" not in out2,
          "attacks key absent when mitre missing")


def test_observable_lifts():
    section("8. `file.path` and `process.pid` lifted from data when present")
    ev = _ev(EventCategory.DETECTION_YARA, Severity.HIGH,
             data={"filepath": r"C:\evil\dropper.exe", "pid": 1234,
                   "name": "dropper.exe", "cmdline": "dropper.exe --go"})
    out = event_to_ocsf(ev)
    check(out.get("file", {}).get("path") == r"C:\evil\dropper.exe",
          "file.path lifted")
    check(out.get("file", {}).get("name") == "dropper.exe",
          "file.name derived from path basename")
    check(out.get("process", {}).get("pid") == 1234,
          "process.pid lifted")
    check(out.get("process", {}).get("name") == "dropper.exe",
          "process.name lifted")


def test_metadata_block():
    section("9. metadata block has product + schema version")
    ev = _ev(EventCategory.SYSTEM_START)
    out = event_to_ocsf(ev, product_name="Aegis-Test",
                        product_version="9.9.9",
                        schema_version="1.1.0")
    md = out["metadata"]
    check(md["version"] == "1.1.0", "metadata.version reflects schema")
    check(md["product"]["name"] == "Aegis-Test",
          "product.name from kwarg")
    check(md["product"]["version"] == "9.9.9",
          "product.version from kwarg")
    check(md["uid"] == ev.event_id,
          "metadata.uid carries AEGIS event_id")


def test_helpers_introspection():
    section("10. mapping_for / supported_categories helpers")
    check(mapping_for("detection.yara") == (2, 2004, 1),
          "mapping_for known category returns triple")
    check(mapping_for("not.a.real.category") is None,
          "mapping_for unknown returns None (catch-all is implicit)")
    check("detection.honeytoken" in supported_categories(),
          "supported_categories lists honeytoken")


def test_unknown_category_falls_back():
    section("11. Unknown categories use the catch-all triple gracefully")
    ev = Event(
        category="not.a.real.category",  # type: ignore[arg-type]
        severity=Severity.MEDIUM,
        source="test",
        data={},
        timestamp=1700000000.0,
    )
    out = event_to_ocsf(ev)
    cat_uid, class_uid, act_id = _DEFAULT_TRIPLE
    check(out["category_uid"] == cat_uid, "category_uid is catch-all")
    check(out["class_uid"] == class_uid, "class_uid is catch-all")
    check(out["activity_id"] == act_id, "activity_id is catch-all")
    check(out["type_uid"] == class_uid * 100 + act_id,
          "type_uid still consistent with formula")


# ── OcsfFileSink end-to-end ─────────────────────────────────────────

def test_sink_disabled_writes_nothing():
    section("12. OcsfFileSink with enabled=false writes no file")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ocsf_off_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    sink = OcsfFileSink(bus, {"enabled": False, "path": str(tmp / "ocsf.json")})
    sink.start()
    bus.publish(_ev(EventCategory.DETECTION_YARA, Severity.HIGH))
    sink.stop()
    check(not (tmp / "ocsf.json").exists(),
          "no file produced when sink disabled")


def test_sink_e2e():
    section("13. OcsfFileSink end-to-end: every event → one JSON line")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ocsf_e2e_"))
    out_path = tmp / "ocsf.json"
    bus = EventBus(db_path=str(tmp / "events.db"))
    sink = OcsfFileSink(bus, {
        "enabled": True,
        "path": str(out_path),
        "product_name": "AEGIS-test",
        "product_version": "test-1",
    })
    sink.start()

    bus.publish(_ev(EventCategory.SYSTEM_START))
    bus.publish(_ev(EventCategory.DETECTION_YARA, Severity.HIGH,
                    data={"rule_id": "evil", "filepath": "/tmp/x"},
                    mitre="T1059"))
    bus.publish(_ev(EventCategory.DETECTION_HONEYTOKEN, Severity.HIGH,
                    data={"action": "canary_modified",
                          "path": "/home/x/wallet.dat",
                          "template": "wallet"},
                    mitre="T1083"))
    sink.stop()

    raw = out_path.read_text(encoding="utf-8").strip().splitlines()
    check(len(raw) == 3, f"three JSON-lines emitted (got {len(raw)})")

    parsed = [json.loads(line) for line in raw]
    check(all("category_uid" in p and "class_uid" in p
              and "type_uid" in p for p in parsed),
          "every line has the OCSF required headers")
    check(parsed[1]["class_uid"] == 2004 and parsed[1]["type_uid"] == 200401,
          "YARA detection mapped to Detection Finding (2004) / Create (1)")
    check(parsed[2].get("attacks", [{}])[0].get("technique", {}).get("uid") == "T1083",
          "honeytoken event carries T1083 in attacks block")
    check(parsed[1]["metadata"]["product"]["name"] == "AEGIS-test",
          "product_name kwarg threaded through to file output")


def test_sink_swallows_mapper_failure():
    section("14. Sink swallows mapper exceptions; never breaks the bus")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ocsf_err_"))
    out_path = tmp / "ocsf.json"
    bus = EventBus(db_path=str(tmp / "events.db"))
    sink = OcsfFileSink(bus, {"enabled": True, "path": str(out_path)})
    sink.start()

    # Patch the mapper to blow up on every call.
    import aegis.utils.alerting as alerting_mod
    original_mapper = alerting_mod.event_to_ocsf
    alerting_mod.event_to_ocsf = lambda *a, **kw: (_ for _ in ()).throw(
        RuntimeError("synthetic mapper failure")
    )
    try:
        # The publish must not raise — that'd corrupt the bus state.
        try:
            bus.publish(_ev(EventCategory.DETECTION_YARA, Severity.HIGH))
            published_ok = True
        except Exception:
            published_ok = False
        check(published_ok,
              "bus.publish does not raise when sink mapper fails")
    finally:
        alerting_mod.event_to_ocsf = original_mapper
        sink.stop()


def main():
    print("=" * 60)
    print("AEGIS — OCSF Export Test")
    print("=" * 60)

    test_every_category_mapped()
    test_category_uids_are_legal()
    test_type_uid_formula()
    test_time_is_milliseconds()
    test_severity_table_exact()
    test_unmapped_preserves_payload()
    test_attacks_block_when_mitre_present()
    test_observable_lifts()
    test_metadata_block()
    test_helpers_introspection()
    test_unknown_category_falls_back()
    test_sink_disabled_writes_nothing()
    test_sink_e2e()
    test_sink_swallows_mapper_failure()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
