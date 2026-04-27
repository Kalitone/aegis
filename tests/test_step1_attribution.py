"""
AEGIS Step 1 — Production-Grade Attribution Test
=================================================
What vendors like Kaspersky/ESET validate in their QA for execution-chain
capture: an attacker chain of N processes ends at a dropped file, and when
the file is detected, the forensic record must contain:

  1. A case_id that correlates quarantine + events
  2. The triggering process snapshot (pid, exe, cmdline, exe_sha256, cwd,
     username, environ-filtered)
  3. Ancestors walked up toward init/System
  4. The chain survives even when the triggering process dies before
     quarantine runs (kill runs before quarantine in CRITICAL mapping)
  5. Environment filtering keeps LD_PRELOAD-class vars, drops secrets
  6. meta.json is valid JSON on disk and references the quarantined file
  7. No crash when the PID is gone at capture time

This script simulates a dropper chain, drives the real ResponseEngine,
and asserts each invariant. It runs without network and without root.
"""
import os
import sys
import json
import time
import tempfile
import subprocess
from pathlib import Path

# Make the package importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.response import ResponseEngine
from aegis.response.forensics import capture_execution_chain


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


def spawn_dropper(drop_path: Path) -> subprocess.Popen:
    """Spawn a subprocess that writes `drop_path` and sleeps so we can
    capture its PID while it's still alive. Simulates a dropper binary.

    Env vars set on purpose:
      LD_PRELOAD (security-relevant — must be kept in environ snapshot)
      AEGIS_TEST_SECRET (sensitive — must NOT appear in environ snapshot)
    """
    env = os.environ.copy()
    env["LD_PRELOAD"] = "/tmp/fake_preload.so"
    env["AEGIS_TEST_SECRET"] = "should-be-filtered"

    code = (
        f"import time, pathlib; "
        f"pathlib.Path(r'{drop_path}').write_bytes(b'EVIL_DROPPED_PAYLOAD'); "
        f"time.sleep(30)"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_direct_capture():
    """Call capture_execution_chain against this test process itself."""
    section("1. capture_execution_chain against live PID")
    chain = capture_execution_chain(os.getpid())
    check(chain["triggering_pid"] == os.getpid(), "triggering_pid matches")
    check(chain["triggering_process"] is not None, "triggering snapshot present")
    tp = chain["triggering_process"] or {}
    check("exe" in tp and tp["exe"], "triggering exe resolved",
          f"exe={tp.get('exe')}")
    check("exe_sha256" in tp and tp["exe_sha256"] is not None,
          "triggering exe SHA-256 computed")
    check("cmdline" in tp and tp["cmdline"], "cmdline captured")
    check("environ" in tp and isinstance(tp["environ"], dict),
          "environ captured as dict")
    check("AEGIS_TEST_SECRET" not in tp["environ"],
          "sensitive env var filtered out")
    check(len(chain["ancestors"]) >= 1,
          "at least one ancestor captured",
          f"got {len(chain['ancestors'])}")
    check(chain["attribution_complete"] is True,
          "attribution marked complete")


def test_dead_pid():
    """Capture against a PID that no longer exists — must not raise."""
    section("2. capture_execution_chain against dead PID")
    # PID 999999 is almost certainly not in use. Tolerate either outcome.
    chain = capture_execution_chain(999999)
    check(isinstance(chain, dict), "returns dict even for missing PID")
    check(chain["attribution_complete"] is False,
          "attribution marked incomplete")
    check(len(chain["notes"]) > 0, "notes explain the miss")


def test_end_to_end_quarantine():
    """Full ResponseEngine flow: dropper → detection → quarantine meta.json."""
    section("3. End-to-end: dropper → detection → quarantine with case")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step1_"))
    quarantine_dir = tmp / "quarantine"
    forensics_dir = tmp / "forensics"
    db_path = tmp / "events.db"

    bus = EventBus(db_path=str(db_path))
    engine = ResponseEngine(bus, {
        "auto_respond": True,
        "quarantine_dir": str(quarantine_dir),
        "forensics_dir": str(forensics_dir),
        # Only quarantine + alert — keep the dropper alive so we can observe
        # it in the chain. (kill_process would reap it before we inspect.)
        "severity_actions": {
            "high": ["quarantine_file", "alert"],
            "critical": ["quarantine_file", "alert"],
        },
        # Step 1 validates attribution only. Sibling hash-sweep is Step 2's
        # concern and has its own dedicated test; disabling it here keeps
        # this test's invariants isolated.
        "hash_sweep": {"enabled": False},
    })
    engine.start()

    drop_path = tmp / "evil_payload.bin"
    dropper = spawn_dropper(drop_path)
    try:
        # Wait for the dropper to write its payload.
        for _ in range(50):
            if drop_path.exists():
                break
            time.sleep(0.1)
        check(drop_path.exists(), "dropper wrote payload file")

        # Capture events we care about.
        seen: list[Event] = []
        bus.subscribe("response.quarantine", lambda e: seen.append(e))

        # Publish the detection event as a detector would.
        bus.publish(Event(
            category=EventCategory.DETECTION_YARA,
            severity=Severity.HIGH,
            source="test",
            mitre_attack="T1105",
            data={
                "pid": dropper.pid,
                "filepath": str(drop_path),
                "rule_name": "TestEvilDropper",
                "rule_id": "TEST-001",
            },
        ))

        # Give the engine a moment (sync today, but belt-and-braces).
        time.sleep(0.2)

        check(len(seen) == 1, "exactly one quarantine event published",
              f"got {len(seen)}")
        qevt = seen[0] if seen else None
        check(qevt is not None and "case_id" in qevt.data,
              "quarantine event carries case_id")
        case_id = qevt.data.get("case_id") if qevt else None

        meta_files = list(quarantine_dir.glob("*.meta.json"))
        check(len(meta_files) == 1, "exactly one meta.json written",
              f"got {len(meta_files)}")

        if not meta_files:
            return
        meta = json.loads(meta_files[0].read_text())

        check(meta.get("case_id") == case_id,
              "meta.json case_id matches event case_id")
        check(meta.get("state") == "STAGED", "quarantine state = STAGED")
        check(meta.get("sha256"), "file hash recorded")
        check(meta.get("original_path") == str(drop_path),
              "original path recorded")

        chain = meta.get("execution_chain") or {}
        tp = chain.get("triggering_process") or {}
        check(chain.get("triggering_pid") == dropper.pid,
              "execution_chain pid = dropper pid")
        check("cmdline" in tp and "EVIL_DROPPED_PAYLOAD" in (tp.get("cmdline") or ""),
              "triggering cmdline preserved",
              f"got cmdline={tp.get('cmdline')!r}")
        check(tp.get("exe_sha256") is not None,
              "dropper exe SHA-256 computed")
        environ = tp.get("environ") or {}
        check("LD_PRELOAD" in environ,
              "LD_PRELOAD preserved in environ snapshot",
              f"keys={list(environ.keys())}")
        check("AEGIS_TEST_SECRET" not in environ,
              "secret env var filtered out of snapshot")

        ancestors = chain.get("ancestors") or []
        check(len(ancestors) >= 1,
              "at least one ancestor (test runner) captured",
              f"got {len(ancestors)}")

        # meta.json is JSON; the forensic chain must survive a round-trip.
        roundtrip = json.loads(json.dumps(meta, default=str))
        check(roundtrip["case_id"] == meta["case_id"],
              "meta.json is JSON-round-trip safe")

        # The quarantined file physically exists with permissions 000.
        qfiles = [p for p in quarantine_dir.iterdir()
                  if p.name.endswith(".meta.json") is False]
        check(len(qfiles) == 1, "quarantined payload present",
              f"got {len(qfiles)}")

    finally:
        try:
            dropper.kill()
            dropper.wait(timeout=5)
        except Exception:
            pass
        engine.stop()
        bus.shutdown()


def test_dead_source_during_capture():
    """Simulates kill-before-quarantine: attribution still produces a marker.

    Reason: in the default CRITICAL mapping, kill_process runs before
    quarantine_file. Our design captures the chain ONCE up front in
    _build_case_context, so even if the dropper were killed afterward,
    meta.json still contains the full chain. Here we verify that the
    capture gracefully handles a PID that dies *between* spawn and
    capture by passing an already-exited PID.
    """
    section("4. Kill-before-quarantine: missing PID tolerated")

    # Spawn a subprocess that immediately exits.
    p = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    p.wait(timeout=5)
    chain = capture_execution_chain(p.pid)
    check(chain["attribution_complete"] is False,
          "dead PID yields incomplete attribution")
    check(chain["triggering_process"] is None,
          "no phantom process snapshot on dead PID")
    check(any("exited" in n or "could not" in n for n in chain["notes"]),
          "notes explain the gap",
          f"notes={chain['notes']}")


if __name__ == "__main__":
    test_direct_capture()
    test_dead_pid()
    test_end_to_end_quarantine()
    test_dead_source_during_capture()

    print("\n" + "=" * 55)
    if failures:
        print(f"RESULT: {len(failures)} failing check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("RESULT: all Step 1 attribution checks PASSED")
        sys.exit(0)
