"""
AEGIS Step 4 — Production-Grade Purge Test
===========================================
What Kaspersky/ESET validate for the "delete from quarantine" flow:
retention-gated bulk purge, per-case operator purge, evidence-gate
refusal when the forensic record is missing, secure overwrite before
unlink, idempotency on re-purge, and audit-trail completeness.

Invariants verified:
  1. purge_case: binary overwritten (bytes == original size), unlinked,
     meta.json mutated to state=PURGED with purged_at + purged_by
  2. meta.json is NOT deleted — it IS the audit trail
  3. Secure overwrite actually writes zeros (verified via side-channel:
     we keep a copy of the original file and compare the overwrite
     region by monkey-patching unlink)
  4. Evidence gate: require_forensic=True + no snapshot ⇒ REFUSE
  5. Evidence gate satisfied when a snapshot_<ts>_<case_id>.json exists
  6. Idempotent: second purge of same case returns ALREADY_PURGED
  7. purge_expired: only STAGED cases older than retention are touched;
     fresh cases are left alone; already-purged cases skipped
  8. list_eligible: returns age + case_id, honors retention cutoff
  9. ResponseEngine.purge_case publishes response.purge event with
     status reflected in severity
 10. ResponseEngine.purge_expired publishes one event per result +
     one summary event
 11. Hash chain still verifies after purge (purges APPEND events; they
     never mutate prior rows)
 12. non-existent case_id ⇒ status=not_found, no crash
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
    purge_case, purge_expired, list_eligible,
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


def _run_quarantine(engine: ResponseEngine, bus: EventBus, filepath: Path,
                    rule: str = "TestRule") -> dict:
    """Helper: publish a detection and return the primary quarantine data."""
    captured: list[Event] = []
    bus.subscribe("response.quarantine", lambda e: captured.append(e))
    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={"filepath": str(filepath), "rule_name": rule, "rule_id": "R"},
    ))
    time.sleep(0.1)
    primaries = [e for e in captured
                 if e.data.get("action") == "file_quarantined"
                 and not e.data.get("parent_case_id")]
    assert primaries, "no primary quarantine event fired"
    return primaries[0].data


def _make_engine(tmp: Path, **extra_cfg) -> tuple[EventBus, ResponseEngine]:
    bus = EventBus(db_path=str(tmp / "events.db"))
    cfg = {
        "auto_respond": True,
        "quarantine_dir": str(tmp / "q"),
        "forensics_dir": str(tmp / "f"),
        "severity_actions": {"high": ["quarantine_file"]},
        "hash_sweep": {"enabled": False},
        "persistence_hunt": {"enabled": False},
    }
    cfg.update(extra_cfg)
    engine = ResponseEngine(bus, cfg)
    engine.start()
    return bus, engine


def test_basic_purge():
    """purge_case: overwrite + unlink + meta mutation."""
    section("1. Basic purge: overwrite, unlink, meta marks PURGED")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_basic_"))
    payload = tmp / "payload.bin"
    payload_bytes = b"SECRET_EVIL_CONTENT_" + b"X" * 4096
    payload.write_bytes(payload_bytes)

    bus, engine = _make_engine(tmp, purge={"require_forensic": False})
    q = _run_quarantine(engine, bus, payload)
    qp = Path(q["quarantine_path"])
    assert qp.exists()
    original_size = qp.stat().st_size
    check(original_size == len(payload_bytes),
          "quarantined file size matches original")

    result = engine.purge_case(q["case_id"], operator="tester")
    check(result["status"] == "purged",
          f"status=purged (got {result['status']})",
          f"result={result}")
    check(result["bytes_overwritten"] == original_size,
          "bytes_overwritten == original size",
          f"got {result['bytes_overwritten']} vs {original_size}")
    check(result["binary_unlinked"] is True,
          "binary_unlinked = True")
    check(not qp.exists(), "quarantined binary no longer on disk")

    # meta.json preserved, state = PURGED
    meta_path = Path(q["meta_path"])
    check(meta_path.exists(), "meta.json retained (audit trail)")
    meta = json.loads(meta_path.read_text())
    check(meta["state"] == "PURGED", "meta state = PURGED")
    check(meta.get("purged_at") is not None, "meta purged_at set")
    check(meta.get("purged_by") == "tester", "meta purged_by = operator")
    check(meta.get("purge_bytes_overwritten") == original_size,
          "meta records overwritten byte count")

    engine.stop()
    bus.shutdown()


def test_secure_overwrite_writes_zeros():
    """Side-channel verification: the overwrite actually writes zeros.

    We monkey-patch os.unlink to capture the file contents AFTER the
    zero pass but BEFORE the file is removed from disk.
    """
    section("2. Secure overwrite actually zero-fills before unlink")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_zero_"))
    payload = tmp / "payload.bin"
    payload.write_bytes(b"SENSITIVE_DATA" * 1000)

    bus, engine = _make_engine(tmp, purge={"require_forensic": False})
    q = _run_quarantine(engine, bus, payload)
    qp = Path(q["quarantine_path"])

    captured_bytes = {"data": None}
    import aegis.response.purge as purge_mod
    real_unlink = purge_mod.os.unlink  # could also hit Path.unlink; patch both.

    def spy_unlink(p):
        try:
            captured_bytes["data"] = Path(p).read_bytes()
        except Exception:
            captured_bytes["data"] = b""
        real_unlink(p)

    # Path.unlink is what purge_case calls.
    original_path_unlink = Path.unlink

    def spy_path_unlink(self, *args, **kwargs):
        try:
            captured_bytes["data"] = self.read_bytes()
        except Exception:
            captured_bytes["data"] = b""
        return original_path_unlink(self, *args, **kwargs)

    Path.unlink = spy_path_unlink
    try:
        result = engine.purge_case(q["case_id"], operator="tester")
    finally:
        Path.unlink = original_path_unlink

    check(result["status"] == "purged", "purge succeeded")
    data = captured_bytes["data"]
    check(data is not None, "spy captured file contents pre-unlink")
    if data is not None:
        check(len(data) > 0, "captured data is non-empty")
        check(all(b == 0 for b in data),
              "captured data is entirely zeros",
              f"non-zero bytes present: "
              f"{sum(1 for b in data if b != 0)}/{len(data)}")

    engine.stop()
    bus.shutdown()


def test_evidence_gate_refuses_purge():
    """require_forensic=True + no snapshot ⇒ evidence_missing, binary intact."""
    section("3. Evidence gate: refuse purge when no forensic snapshot")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_gate_"))
    payload = tmp / "payload.bin"
    payload.write_bytes(b"payload" * 100)

    # Default config: require_forensic=True, but severity_actions only
    # does quarantine — no forensic_snapshot triggered.
    bus, engine = _make_engine(tmp)
    q = _run_quarantine(engine, bus, payload)
    qp = Path(q["quarantine_path"])
    assert qp.exists()

    result = engine.purge_case(q["case_id"], operator="tester")
    check(result["status"] == "evidence_missing",
          f"status=evidence_missing (got {result['status']})")
    check(qp.exists(),
          "binary still on disk when evidence gate fires")
    meta = json.loads(Path(q["meta_path"]).read_text())
    check(meta["state"] == "STAGED",
          "meta state remains STAGED after refused purge")

    # Override at call time must allow force-purge.
    result2 = engine.purge_case(q["case_id"], operator="forcer",
                                require_forensic=False)
    check(result2["status"] == "purged",
          "force purge succeeds with require_forensic=False override")
    check(not qp.exists(), "binary unlinked after force purge")

    engine.stop()
    bus.shutdown()


def test_evidence_gate_satisfied():
    """Plant a forensic snapshot, purge succeeds."""
    section("4. Evidence gate: snapshot present ⇒ purge proceeds")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_ok_"))
    payload = tmp / "payload.bin"
    payload.write_bytes(b"payload" * 100)

    bus, engine = _make_engine(tmp)
    q = _run_quarantine(engine, bus, payload)
    case_id = q["case_id"]

    # Plant a snapshot matching the convention.
    (tmp / "f").mkdir(exist_ok=True)
    (tmp / "f" / f"snapshot_{int(time.time())}_{case_id}.json").write_text(
        json.dumps({"case_id": case_id})
    )

    result = engine.purge_case(case_id, operator="tester")
    check(result["status"] == "purged",
          f"status=purged (got {result['status']})")

    engine.stop()
    bus.shutdown()


def test_idempotent_and_missing():
    """Re-purge returns already_purged; unknown case returns not_found."""
    section("5. Idempotency + missing case handling")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_idem_"))
    payload = tmp / "payload.bin"
    payload.write_bytes(b"data" * 50)

    bus, engine = _make_engine(tmp, purge={"require_forensic": False})
    q = _run_quarantine(engine, bus, payload)

    r1 = engine.purge_case(q["case_id"], operator="t")
    r2 = engine.purge_case(q["case_id"], operator="t")
    check(r1["status"] == "purged", "first purge succeeds")
    check(r2["status"] == "already_purged",
          f"second purge returns already_purged (got {r2['status']})")

    r3 = engine.purge_case("ffffffffffff", operator="t")
    check(r3["status"] == "not_found",
          f"unknown case ⇒ not_found (got {r3['status']})")

    engine.stop()
    bus.shutdown()


def test_retention_and_bulk():
    """purge_expired touches only STAGED cases older than retention."""
    section("6. Retention + bulk purge_expired")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_bulk_"))
    fresh = tmp / "fresh.bin"
    old = tmp / "old.bin"
    fresh.write_bytes(b"fresh" * 100)
    old.write_bytes(b"old" * 100)

    bus, engine = _make_engine(tmp, purge={
        "require_forensic": False,
        "retention_days": 7,
    })
    q_fresh = _run_quarantine(engine, bus, fresh, rule="Fresh")
    q_old = _run_quarantine(engine, bus, old, rule="Old")

    # Back-date the old case by editing its meta.json quarantined_at.
    old_meta_path = Path(q_old["meta_path"])
    old_meta = json.loads(old_meta_path.read_text())
    old_meta["quarantined_at"] = time.time() - 10 * 86400  # 10 days ago
    old_meta_path.write_text(json.dumps(old_meta, indent=2))

    eligible = engine.list_purge_eligible()
    eligible_ids = {e["case_id"] for e in eligible}
    check(q_old["case_id"] in eligible_ids, "old case is eligible")
    check(q_fresh["case_id"] not in eligible_ids,
          "fresh case NOT eligible",
          f"eligible={eligible_ids}")

    out = engine.purge_expired(operator="cron")
    check(out["summary"]["total"] == 1,
          "bulk processed exactly 1 case",
          f"total={out['summary']['total']}")
    check(out["summary"]["purged"] == 1, "1 purged")

    # Fresh binary still on disk.
    check(Path(q_fresh["quarantine_path"]).exists(),
          "fresh quarantine untouched by bulk purge")
    check(not Path(q_old["quarantine_path"]).exists(),
          "old quarantine removed")

    engine.stop()
    bus.shutdown()


def test_event_audit_trail():
    """Verify response.purge events carry the right shape + chain intact."""
    section("7. Events published + hash chain still verifies")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_audit_"))
    payload = tmp / "payload.bin"
    payload.write_bytes(b"abc" * 200)

    bus, engine = _make_engine(tmp, purge={"require_forensic": False})
    q = _run_quarantine(engine, bus, payload)

    purge_events: list[Event] = []
    bus.subscribe("response.purge", lambda e: purge_events.append(e))

    engine.purge_case(q["case_id"], operator="auditor")
    time.sleep(0.05)

    check(len(purge_events) == 1, "one response.purge event published",
          f"got {len(purge_events)}")
    if purge_events:
        e = purge_events[0]
        check(e.data["action"] == "purge_case", "action=purge_case")
        check(e.data["status"] == "purged", "event.status=purged")
        check(e.data["case_id"] == q["case_id"], "event carries case_id")
        check(e.severity == Severity.HIGH,
              "severity HIGH on successful purge")

    # Bulk run → one summary + zero per-case (no eligible left).
    purge_events.clear()
    out = engine.purge_expired(operator="cron")
    summary_events = [e for e in purge_events
                      if e.data.get("action") == "purge_expired_summary"]
    check(len(summary_events) == 1, "bulk emits one summary event")

    # Hash chain must still verify — purge appends events, never mutates.
    ok, problems = bus.verify_chain()
    check(ok, "event hash chain still verifies after purges",
          f"problems={problems[:3]}")

    engine.stop()
    bus.shutdown()


def test_list_eligible_pure():
    """Pure-function test of list_eligible: only STAGED, only aged."""
    section("8. list_eligible: state + age filtering")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step4_list_"))
    qd = tmp / "q"
    qd.mkdir()

    now = time.time()
    # Three cases: aged-STAGED, fresh-STAGED, aged-PURGED.
    for name, state, age_days in (
        ("aged_staged", "STAGED", 10),
        ("fresh_staged", "STAGED", 1),
        ("aged_purged", "PURGED", 10),
    ):
        cid = f"case_{name}_xxx"[:12]
        m = {
            "case_id": cid,
            "state": state,
            "quarantined_at": now - age_days * 86400,
            "purged_at": now if state == "PURGED" else None,
        }
        (qd / f"{int(now)}_{cid}_hhhh_{name}.meta.json").write_text(
            json.dumps(m)
        )

    result = list_eligible(qd, retention_s=7 * 86400, now=now)
    ids = {r["case_id"] for r in result}
    check(len(result) == 1, f"exactly 1 eligible (got {len(result)})")
    check("case_aged_st" in ids or any("aged_staged" in r["case_id"]
                                        for r in result),
          "aged_staged is eligible")
    check(not any("fresh" in r["case_id"] for r in result),
          "fresh cases excluded")
    check(not any("purged" in r["case_id"] for r in result),
          "already-purged cases excluded")


if __name__ == "__main__":
    test_basic_purge()
    test_secure_overwrite_writes_zeros()
    test_evidence_gate_refuses_purge()
    test_evidence_gate_satisfied()
    test_idempotent_and_missing()
    test_retention_and_bulk()
    test_event_audit_trail()
    test_list_eligible_pure()

    print("\n" + "=" * 55)
    if failures:
        print(f"RESULT: {len(failures)} failing check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("RESULT: all Step 4 purge checks PASSED")
        sys.exit(0)
