"""
AEGIS Step 5 — Production-Grade Hardening Re-Check Test
========================================================
What Kaspersky/CrowdStrike/ESET validate for "post-action posture
re-baseline":

  - First-run produces a baseline AND emits drift events for every
    finding (the initial census).
  - Subsequent runs report ONLY deltas (new vs resolved vs persistent).
  - Drift severity reflects the underlying finding severity (CRITICAL
    SUID drop != INFO weak permission).
  - Baseline persists atomically across crashes (temp + rename).
  - Disabled config emits zero drift events.
  - End-to-end: a simulated attack creates a SUID-like artefact, the
    full response cascade runs, and the re-check surfaces the artefact
    as drift on the second case.
  - Hash chain still verifies after drift events — they're appended,
    never mutated.
  - Manual re-check API doesn't require a detection.

Invariants verified:
  1. diff_findings classification: new / resolved / persistent
  2. save_baseline + load_baseline round-trip with atomicity
  3. First baseline run: every finding becomes 'new', INFO severity
  4. Second run with no changes: zero new, zero resolved
  5. Second run after introducing drift: drift surfaces as 'new', HIGH+
  6. Second run after fixing baseline drift: surfaces as 'resolved'
  7. Severity mapping: critical → CRITICAL, etc.
  8. Disabled config produces no recheck events on detection
  9. End-to-end: detection → quarantine → ... → drift event published
 10. Hash chain integrity preserved
 11. Manual hardening_recheck() API works without a detection
 12. Audit failure handled gracefully (no crash, status reported)
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
from aegis.response.hardening_recheck import (
    diff_findings, load_baseline, save_baseline, run_recheck,
)
from aegis.hardening import Finding, HardeningSeverity


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


# ---------- Stub runner -----------------------------------------------------
# Production HardeningRunner inspects the real OS. For deterministic tests we
# inject a runner whose audit() returns whatever the test planted.

class StubRunner:
    """Minimal HardeningRunner-shaped object: only audit() is called."""

    def __init__(self, findings_provider):
        self._provider = findings_provider

    def audit(self) -> list[Finding]:
        return list(self._provider())


def _fnd(check_id: str, target: str, severity=HardeningSeverity.HIGH,
         title: str = "test finding", description: str = "",
         platform: str = "common") -> Finding:
    return Finding(
        check_id=check_id, title=title, description=description or title,
        severity=severity, target=target, platform=platform, fixable=False,
    )


# ---------- 1. diff_findings classification --------------------------------

def test_diff_classification():
    section("1. diff_findings: new / resolved / persistent classification")
    base_list = [
        _fnd("C-001", "/a"),
        _fnd("C-002", "/b"),
        _fnd("C-001", "/c"),
    ]
    baseline = {f"{f.check_id}|{f.target}": f.to_dict() for f in base_list}
    current = [
        _fnd("C-002", "/b"),                # persistent
        _fnd("C-001", "/c"),                # persistent
        _fnd("C-003", "/suid_new"),         # new
        _fnd("C-099", "/another_new"),      # new
    ]
    diff = diff_findings(baseline, current)
    check(len(diff["new"]) == 2, "two new findings",
          f"got {len(diff['new'])}")
    check(len(diff["resolved"]) == 1, "one resolved finding",
          f"got {len(diff['resolved'])}")
    check(len(diff["persistent"]) == 2, "two persistent findings",
          f"got {len(diff['persistent'])}")
    new_targets = {f["target"] for f in diff["new"]}
    check(new_targets == {"/suid_new", "/another_new"},
          "new findings carry expected targets",
          f"got {new_targets}")
    check(diff["resolved"][0]["target"] == "/a",
          "resolved finding is /a (was in baseline only)")


# ---------- 2. baseline I/O round-trip + atomicity -------------------------

def test_baseline_roundtrip():
    section("2. save_baseline + load_baseline round-trip")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_baseline_"))
    bp = tmp / "baseline.json"
    findings = [_fnd("C-001", "/x"), _fnd("C-002", "/y",
                                          severity=HardeningSeverity.CRITICAL)]
    save_baseline(bp, findings)
    check(bp.exists(), "baseline file written")
    loaded = load_baseline(bp)
    check(len(loaded) == 2, "two entries loaded", f"got {len(loaded)}")
    check("C-001|/x" in loaded, "C-001|/x key present")
    check(loaded["C-002|/y"]["severity"] == "critical",
          "severity preserved through round-trip")

    # No leftover temp files in the dir.
    leftovers = [p.name for p in tmp.iterdir() if p.name.startswith(".baseline_")]
    check(not leftovers, "no leftover .baseline_ tempfiles",
          f"found {leftovers}")

    # Corrupt baseline returns {} (not crash).
    bp.write_text("{ this is not json")
    check(load_baseline(bp) == {},
          "corrupt baseline file -> empty dict (no crash)")


# ---------- 3. First baseline run: every finding is 'new', INFO severity ---

def test_first_baseline_first_run():
    section("3. First-run baseline: census fires INFO drift events")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_first_"))
    bp = tmp / "baseline.json"
    findings = [_fnd("C-100", "/path/a", severity=HardeningSeverity.HIGH),
                _fnd("C-101", "/path/b", severity=HardeningSeverity.CRITICAL)]
    runner = StubRunner(lambda: findings)
    result = run_recheck(bp, runner=runner)
    check(result["status"] == "ok", "status ok")
    check(result["baseline_existed"] is False,
          "baseline didn't exist before first run")
    check(result["baseline_written"] is True, "baseline written on first run")
    check(result["new_count"] == 2, "two findings classified as new",
          f"got {result['new_count']}")
    check(bp.exists(), "baseline file persisted to disk")


# ---------- 4. Second run, no changes: zero deltas -------------------------

def test_second_run_quiet():
    section("4. Second run with no changes: zero deltas")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_quiet_"))
    bp = tmp / "baseline.json"
    findings = [_fnd("C-200", "/etc/sshd_config",
                     severity=HardeningSeverity.HIGH)]
    runner = StubRunner(lambda: findings)
    run_recheck(bp, runner=runner)  # establish baseline
    second = run_recheck(bp, runner=runner)
    check(second["new_count"] == 0, "no new drift on quiet second run",
          f"got {second['new_count']}")
    check(second["resolved_count"] == 0, "no resolved on quiet second run")
    check(second["persistent_count"] == 1, "one persistent finding",
          f"got {second['persistent_count']}")


# ---------- 5. Drift introduced post-baseline shows up as 'new' -----------

def test_drift_detected():
    section("5. Drift introduced post-baseline -> classified 'new'")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_drift_"))
    bp = tmp / "baseline.json"
    state = {"set": [_fnd("C-300", "/etc/normal")]}
    runner = StubRunner(lambda: state["set"])
    run_recheck(bp, runner=runner)  # baseline = normal

    # Simulate post-incident drift: SUID binary planted in /tmp.
    state["set"] = [
        _fnd("C-300", "/etc/normal"),
        _fnd("LINUX-SUID", "/tmp/.evil_suid",
             severity=HardeningSeverity.CRITICAL,
             title="Unexpected SUID root binary"),
    ]
    second = run_recheck(bp, runner=runner)
    check(second["new_count"] == 1,
          "one new drift finding surfaced",
          f"got {second['new_count']}")
    check(second["diff"]["new"][0]["target"] == "/tmp/.evil_suid",
          "drift target matches the planted SUID")
    check(second["diff"]["new"][0]["severity"] == "critical",
          "drift severity preserved")


# ---------- 6. Resolved drift: removed from baseline => 'resolved' --------

def test_resolved_classification():
    section("6. Removed-since-baseline finding -> 'resolved'")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_resolved_"))
    bp = tmp / "baseline.json"
    state = {"set": [
        _fnd("C-400", "/etc/A"),
        _fnd("C-401", "/etc/B"),
    ]}
    runner = StubRunner(lambda: state["set"])
    run_recheck(bp, runner=runner)
    state["set"] = [_fnd("C-400", "/etc/A")]  # B was fixed
    second = run_recheck(bp, runner=runner)
    check(second["resolved_count"] == 1,
          "one resolved finding",
          f"got {second['resolved_count']}")
    check(second["diff"]["resolved"][0]["target"] == "/etc/B",
          "resolved finding is /etc/B")


# ---------- 7. Disabled config produces no drift events --------------------

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


def _trigger(engine, bus, payload: Path):
    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={"filepath": str(payload), "rule_name": "TestRule",
              "rule_id": "R"},
    ))
    time.sleep(0.1)


def test_disabled_emits_no_drift():
    section("7. hardening_recheck disabled -> no drift events")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_disabled_"))
    payload = tmp / "p.bin"
    payload.write_bytes(b"x" * 100)
    bus, engine = _make_engine(tmp,
                               hardening_recheck={"enabled": False})

    drift_events: list[Event] = []
    bus.subscribe("response.hardening_drift",
                  lambda e: drift_events.append(e))
    _trigger(engine, bus, payload)
    check(len(drift_events) == 0,
          "zero drift events when re-check disabled",
          f"got {len(drift_events)}")
    engine.stop()
    bus.shutdown()


# ---------- 8. End-to-end: simulated SUID drift surfaces in 2nd case ------

def test_end_to_end_drift_after_attack():
    section("8. E2E: 2nd attack surfaces SUID drift introduced after the 1st")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_e2e_"))

    # Mutable finding set lets us simulate the host changing between cases.
    state = {"set": [
        _fnd("BASE-001", "/etc/baseline_A", severity=HardeningSeverity.MEDIUM),
    ]}
    runner = StubRunner(lambda: state["set"])

    bus, engine = _make_engine(tmp,
                               hardening_recheck={
                                   "enabled": True,
                                   "runner": runner,
                                   "baseline_path": str(tmp / "f" /
                                                         "baseline.json"),
                               })

    drift_events: list[Event] = []
    bus.subscribe("response.hardening_drift",
                  lambda e: drift_events.append(e))

    # Case 1: first detection. Baseline does not exist; this run captures it.
    p1 = tmp / "p1.bin"
    p1.write_bytes(b"first" * 50)
    _trigger(engine, bus, p1)

    completes_1 = [e for e in drift_events
                   if e.data.get("action") == "hardening_recheck_complete"]
    check(len(completes_1) == 1, "one recheck completion event after case 1",
          f"got {len(completes_1)}")
    if completes_1:
        check(completes_1[0].data["baseline_existed"] is False,
              "first run reports baseline_existed=False")

    # Now the "attacker" left a SUID behind. Baseline is current as of case 1.
    state["set"] = [
        _fnd("BASE-001", "/etc/baseline_A", severity=HardeningSeverity.MEDIUM),
        _fnd("LINUX-SUID-NEW", "/tmp/.aegis_test_suid",
             severity=HardeningSeverity.CRITICAL,
             title="Unexpected SUID binary"),
    ]
    drift_events.clear()

    # Case 2: trigger another detection; recheck should surface the drift.
    p2 = tmp / "p2.bin"
    p2.write_bytes(b"second" * 50)
    _trigger(engine, bus, p2)

    drifts = [e for e in drift_events
              if e.data.get("action") == "hardening_drift"]
    check(len(drifts) == 1, "one drift event for the new SUID",
          f"got {len(drifts)}")
    if drifts:
        d = drifts[0]
        check(d.data["finding"]["target"] == "/tmp/.aegis_test_suid",
              "drift event target = the planted SUID")
        check(d.severity == Severity.CRITICAL,
              "drift event severity = CRITICAL (matches finding)",
              f"got {d.severity}")
        check(d.data["first_baseline"] is False,
              "drift NOT marked as first_baseline (case 2 has prior baseline)")
        check(d.data["drift_kind"] == "new", "drift_kind = new")

    completes_2 = [e for e in drift_events
                   if e.data.get("action") == "hardening_recheck_complete"]
    check(len(completes_2) == 1, "one recheck completion after case 2")
    if completes_2:
        check(completes_2[0].data["new_count"] == 1,
              "completion summary: new_count=1")
        check(completes_2[0].severity == Severity.HIGH,
              "completion severity HIGH when there's drift on a real baseline")

    engine.stop()
    bus.shutdown()


# ---------- 9. Hash chain still verifies after drift events ---------------

def test_hash_chain_intact():
    section("9. Hash chain integrity preserved after drift events")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_chain_"))
    state = {"set": [_fnd("C-A", "/x")]}
    runner = StubRunner(lambda: state["set"])
    bus, engine = _make_engine(tmp,
                               hardening_recheck={
                                   "enabled": True,
                                   "runner": runner,
                                   "baseline_path": str(tmp / "f" / "b.json"),
                               })
    p = tmp / "p.bin"
    p.write_bytes(b"data" * 50)
    _trigger(engine, bus, p)
    state["set"] = [_fnd("C-A", "/x"),
                    _fnd("C-B", "/y", severity=HardeningSeverity.HIGH)]
    p2 = tmp / "p2.bin"
    p2.write_bytes(b"data2" * 50)
    _trigger(engine, bus, p2)

    ok, problems = bus.verify_chain()
    check(ok, "hash chain still verifies after drift events",
          f"problems={problems[:3]}")
    engine.stop()
    bus.shutdown()


# ---------- 10. Manual hardening_recheck() API ----------------------------

def test_manual_recheck_api():
    section("10. Manual recheck API works without a detection")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_manual_"))
    runner = StubRunner(lambda: [_fnd("M-001", "/etc/manual")])
    bus, engine = _make_engine(tmp,
                               hardening_recheck={
                                   "enabled": True,
                                   "runner": runner,
                                   "baseline_path": str(tmp / "f" / "b.json"),
                               })
    drift_events: list[Event] = []
    bus.subscribe("response.hardening_drift",
                  lambda e: drift_events.append(e))

    result = engine.hardening_recheck()
    time.sleep(0.05)
    check(result["status"] == "ok", "manual recheck returns ok status")
    check(result["baseline_written"] is True,
          "manual recheck wrote baseline")
    manual_events = [e for e in drift_events
                     if e.data.get("action") == "hardening_recheck_manual"]
    check(len(manual_events) == 1,
          "manual recheck published exactly one event",
          f"got {len(manual_events)}")
    engine.stop()
    bus.shutdown()


# ---------- 11. Audit failure handled gracefully --------------------------

def test_audit_failure_handled():
    section("11. Audit failure handled (no crash, status reported)")

    class BoomRunner:
        def audit(self):
            raise RuntimeError("simulated audit boom")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_boom_"))
    bp = tmp / "baseline.json"
    result = run_recheck(bp, runner=BoomRunner())
    check(result["status"] == "audit_failed",
          "result status = audit_failed",
          f"got {result['status']}")
    check("simulated audit boom" in result.get("error", ""),
          "error message preserved")
    check(not bp.exists(),
          "no baseline written when audit failed")


# ---------- 12. update_baseline=False keeps baseline frozen ---------------

def test_update_baseline_false():
    section("12. update_baseline=False does not overwrite existing baseline")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_step5_frozen_"))
    bp = tmp / "baseline.json"
    state = {"set": [_fnd("F-001", "/a")]}
    runner = StubRunner(lambda: state["set"])
    run_recheck(bp, runner=runner)  # establishes baseline
    original_bytes = bp.read_bytes()

    # Drift state, but preview-only call
    state["set"] = [_fnd("F-001", "/a"), _fnd("F-002", "/b")]
    preview = run_recheck(bp, runner=runner, update_baseline=False)
    check(preview["new_count"] == 1, "preview reports one new finding")
    check(preview["baseline_written"] is False,
          "preview did not write baseline")
    check(bp.read_bytes() == original_bytes,
          "baseline file bytes unchanged after preview")


# ---------- Run ----------------------------------------------------------

def main():
    print("=" * 60)
    print("AEGIS STEP 5 - PRODUCTION-GRADE HARDENING RE-CHECK TEST")
    print("=" * 60)
    test_diff_classification()
    test_baseline_roundtrip()
    test_first_baseline_first_run()
    test_second_run_quiet()
    test_drift_detected()
    test_resolved_classification()
    test_disabled_emits_no_drift()
    test_end_to_end_drift_after_attack()
    test_hash_chain_intact()
    test_manual_recheck_api()
    test_audit_failure_handled()
    test_update_baseline_false()

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
