"""
AEGIS Step 3 — Production-Grade Persistence Hunt Test
======================================================
What Sysinternals Autoruns / ESET / Kaspersky validate for persistence
discovery: given a malicious file's indicators, every known autostart
surface must be scanned, every referencing entry must be reported with
an actionable location, and false positives must stay out of the report.

Invariants verified:
  1. POSIX surfaces (cron, systemd, profiles, rc.local, ld.so.preload)
     find references injected into fake roots
  2. Windows surfaces (registry Run, startup folder, scheduled tasks)
     find references via mock fixtures — no real registry writes
  3. Indicator matching: paths (full), hashes (substring), basenames
     (min length guard against 'bin'/'run'/etc. false positives)
  4. Benign neighbor files produce zero hits
  5. Per-hit reporting: surface, location, line number, reference,
     matched_indicator, removable (forced False)
  6. Surface failure is isolated — one bad surface doesn't abort others
  7. End-to-end: ResponseEngine runs persistence hunt after quarantine,
     publishes response.persistence event, appends hits to meta.json
  8. Disabled config ⇒ no persistence event
  9. Indicators auto-assembled from primary + siblings (dedup, basename
     extraction)
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
from aegis.response.persistence import (
    hunt_persistence,
    build_indicators_from_quarantine,
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


# The "malicious" file we'll hunt for references to.
EVIL_PATH_POSIX = "/opt/evil/payload_step3_unique.bin"
EVIL_PATH_WIN = r"C:\ProgramData\Evil\payload_step3_unique.bin"
EVIL_BASENAME = "payload_step3_unique.bin"
EVIL_SHA256 = "e" * 60 + "abcd"  # 64-char hex-ish
INDICATORS_POSIX = {
    "paths": [EVIL_PATH_POSIX],
    "basenames": [EVIL_BASENAME],
    "hashes": [EVIL_SHA256],
}
INDICATORS_WIN = {
    "paths": [EVIL_PATH_WIN],
    "basenames": [EVIL_BASENAME],
    "hashes": [EVIL_SHA256],
}


def test_posix_surfaces():
    """Plant fake persistence artifacts in a temp root, hunt, verify
    every surface fires exactly where it should."""
    section("1. POSIX surfaces via injected fake roots")

    root = Path(tempfile.mkdtemp(prefix="aegis_step3_posix_"))
    cron_dir = root / "etc" / "cron.d"
    cron_dir.mkdir(parents=True)
    systemd_dir = root / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)
    profiles_dir = root / "etc" / "profile.d"
    profiles_dir.mkdir(parents=True)
    init_dir = root / "etc" / "init.d"
    init_dir.mkdir(parents=True)

    # Evil references.
    (cron_dir / "evil_job").write_text(
        f"# benign comment\n"
        f"*/5 * * * * root {EVIL_PATH_POSIX} --beacon\n"
    )
    (systemd_dir / "evil.service").write_text(
        "[Unit]\nDescription=Legit-looking\n"
        f"[Service]\nExecStart={EVIL_PATH_POSIX}\n"
    )
    (profiles_dir / "99-evil.sh").write_text(
        f"# injected on login\nexport LD_PRELOAD={EVIL_PATH_POSIX}.so\n"
    )
    rc_local = root / "etc" / "rc.local"
    rc_local.write_text(f"#!/bin/sh\n{EVIL_PATH_POSIX} &\nexit 0\n")
    ld_preload = root / "etc" / "ld.so.preload"
    ld_preload.write_text(f"{EVIL_PATH_POSIX}.so\n")

    # Benign neighbors — must NOT hit.
    (cron_dir / "legit_job").write_text("0 0 * * * root /usr/bin/logrotate\n")
    (systemd_dir / "nginx.service").write_text(
        "[Unit]\n[Service]\nExecStart=/usr/sbin/nginx\n"
    )
    (profiles_dir / "00-colors.sh").write_text("export PS1='$ '\n")

    roots = {
        "cron": [str(cron_dir / "*")],
        "systemd": [str(systemd_dir / "*.service")],
        "profiles": [str(profiles_dir / "*.sh")],
        "init": [str(rc_local)],
        "ld_preload": [str(ld_preload)],
    }

    report = hunt_persistence(INDICATORS_POSIX, roots=roots, platform="posix")
    hits = report["hits"]
    surfaces = {h["surface"] for h in hits}

    check("cron" in surfaces, "cron hit present",
          f"surfaces={surfaces}")
    check("systemd" in surfaces, "systemd hit present")
    check("shell_profile" in surfaces, "shell_profile hit present")
    check("init_script" in surfaces, "init_script hit present")
    check("ld_so_preload" in surfaces, "ld_so_preload hit present")

    check(len(hits) >= 5, "at least 5 hits total",
          f"got {len(hits)}")
    # No false positives from benign files.
    benign_hits = [h for h in hits if "nginx" in h.get("reference", "")
                   or "logrotate" in h.get("reference", "")]
    check(len(benign_hits) == 0, "no false positives from benign entries",
          f"benign_hits={benign_hits}")

    # Each hit has the required fields.
    for h in hits[:1]:
        check("surface" in h and "location" in h and "line" in h
              and "reference" in h and "matched_indicator" in h
              and "removable" in h,
              "hit schema complete")
        check(h["removable"] is False,
              "removable defaults to False (report-only)")
        check(h["matched_indicator"].startswith("path:")
              or h["matched_indicator"].startswith("basename:")
              or h["matched_indicator"].startswith("hash:"),
              "matched_indicator labeled correctly",
              f"got {h['matched_indicator']}")

    # Report bookkeeping.
    check(report["surfaces_scanned"] == [
        "cron", "systemd", "shell_profile", "init_script", "ld_so_preload"
    ], "all posix surfaces scanned",
       f"got {report['surfaces_scanned']}")
    check(len(report["surfaces_failed"]) == 0, "no surface failures",
          f"failed={report['surfaces_failed']}")


def test_windows_surfaces_via_mocks():
    """Windows surfaces can't touch the real registry in tests. Use mock
    fixtures (registry_mock + schtasks_csv + startup_folders)."""
    section("2. Windows surfaces via mock fixtures")

    root = Path(tempfile.mkdtemp(prefix="aegis_step3_win_"))
    startup = root / "Startup"
    startup.mkdir()
    # A batch file referencing the evil path.
    (startup / "launcher.bat").write_text(
        f"@echo off\nstart \"\" \"{EVIL_PATH_WIN}\"\n"
    )
    # A payload dropped directly in startup (filename-only match).
    (startup / EVIL_BASENAME).write_text("")
    # Benign neighbor.
    (startup / "OneDrive.lnk").write_text("(binary-ish)")

    registry_mock = [
        {
            "label": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "values": {
                "EvilUpdater": f'"{EVIL_PATH_WIN}" --silent',
                "LegitAdobe": "C:\\Program Files\\Adobe\\AcroRd32.exe",
            },
        },
        {
            "label": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "values": {
                "Chrome": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            },
        },
    ]

    schtasks_csv = (
        '"HostName","TaskName","Task To Run","Status"\n'
        f'"TESTHOST","\\EvilPersist","{EVIL_PATH_WIN} /run","Ready"\n'
        '"TESTHOST","\\LegitBackup","C:\\Backup\\backup.exe","Ready"\n'
    )

    roots = {
        "startup_folders": [str(startup / "*")],
        "registry_mock": registry_mock,
        "schtasks_csv": schtasks_csv,
    }
    report = hunt_persistence(INDICATORS_WIN, roots=roots, platform="nt")
    hits = report["hits"]
    surfaces = {h["surface"] for h in hits}

    check("registry_run" in surfaces, "registry_run hit present",
          f"surfaces={surfaces}")
    check("startup_folder" in surfaces, "startup_folder hit present")
    check("scheduled_task" in surfaces, "scheduled_task hit present")

    registry_hits = [h for h in hits if h["surface"] == "registry_run"]
    check(len(registry_hits) == 1, "exactly one registry hit (evil only)",
          f"got {len(registry_hits)}: {[h['location'] for h in registry_hits]}")
    if registry_hits:
        check("EvilUpdater" in registry_hits[0]["location"],
              "registry hit points at EvilUpdater value")

    task_hits = [h for h in hits if h["surface"] == "scheduled_task"]
    check(len(task_hits) == 1, "exactly one scheduled-task hit",
          f"got {len(task_hits)}")
    if task_hits:
        check(task_hits[0]["location"] == "\\EvilPersist",
              "scheduled task name preserved",
              f"got {task_hits[0]['location']}")

    # Startup folder: launcher.bat (content) + evil_basename (filename)
    sf_hits = [h for h in hits if h["surface"] == "startup_folder"]
    check(len(sf_hits) >= 2, "startup folder produced >=2 hits",
          f"got {len(sf_hits)}")

    # No false positives: Chrome / Adobe / OneDrive not flagged.
    junk = [h for h in hits if "chrome" in h["reference"].lower()
            or "adobe" in h["reference"].lower()
            or "onedrive" in h["reference"].lower()]
    check(len(junk) == 0, "no false positives from benign neighbors",
          f"junk={junk}")


def test_basename_min_length_guard():
    """Very short basenames must NOT be used as matchers (would hit
    everything — 'run', 'bin', etc.)."""
    section("3. Short basenames are ignored (false-positive guard)")

    root = Path(tempfile.mkdtemp(prefix="aegis_step3_short_"))
    profiles_dir = root / "profile.d"
    profiles_dir.mkdir()
    (profiles_dir / "legit.sh").write_text(
        "# references ssh and bin and run\nexport PATH=/usr/bin:$PATH\n"
    )

    # Indicators with a SHORT basename ('sh' — 2 chars).
    indicators = {"paths": [], "basenames": ["sh"], "hashes": []}
    report = hunt_persistence(
        indicators,
        roots={"profiles": [str(profiles_dir / "*.sh")]},
        platform="posix",
    )
    check(len(report["hits"]) == 0,
          "short basename 'sh' produced zero hits",
          f"got {len(report['hits'])}")
    check(report["indicator_count"] == 0,
          "no matchers built from short basename")


def test_surface_isolation():
    """A broken surface override must not abort the whole hunt."""
    section("4. One broken surface does not fail the rest")

    root = Path(tempfile.mkdtemp(prefix="aegis_step3_iso_"))
    cron_dir = root / "cron.d"
    cron_dir.mkdir()
    (cron_dir / "evil").write_text(f"* * * * * root {EVIL_PATH_POSIX}\n")

    # Point systemd at a directory that doesn't exist — glob returns [].
    # That's not an error actually. Let's trigger a real error: pass
    # something non-iterable where a list is expected.
    report = hunt_persistence(
        INDICATORS_POSIX,
        roots={
            "cron": [str(cron_dir / "*")],
            "systemd": 42,      # wrong type — will crash that scanner
            "profiles": [],
            "init": [],
            "ld_preload": [],
        },
        platform="posix",
    )
    check("cron" in report["surfaces_scanned"],
          "cron still scanned despite systemd failure")
    failed_names = {f["surface"] for f in report["surfaces_failed"]}
    check("systemd" in failed_names,
          "systemd reported as failed",
          f"failed={report['surfaces_failed']}")
    check(len(report["hits"]) >= 1,
          "cron hit still surfaced",
          f"hits={report['hits']}")


def test_build_indicators():
    """build_indicators_from_quarantine assembles the indicator dict
    correctly from primary + sibling records with de-dup."""
    section("5. Indicator assembly from quarantine records")

    primary = {
        "original_path": "/tmp/evil.bin",
        "quarantine_path": "/q/001_evil.bin",
        "sha256": "a" * 64,
    }
    siblings = [
        {"original_path": "/home/user/.cache/evil.bin",
         "quarantine_path": "/q/002_evil.bin",
         "sha256": "a" * 64},  # same hash, dedup test
        {"original_path": "/var/tmp/evil_renamed.bin",
         "quarantine_path": "/q/003_evil_renamed.bin",
         "sha256": "a" * 64},
    ]
    ind = build_indicators_from_quarantine(primary, siblings)
    check("/tmp/evil.bin" in ind["paths"], "primary path present")
    check("/q/001_evil.bin" in ind["paths"], "primary quarantine path present")
    check("/home/user/.cache/evil.bin" in ind["paths"],
          "sibling path present")
    check("evil.bin" in ind["basenames"], "primary basename extracted")
    check("evil_renamed.bin" in ind["basenames"],
          "sibling basename extracted")
    # Dedup: hash appears once.
    check(ind["hashes"].count("a" * 64) == 1,
          "duplicate hashes de-duplicated",
          f"hashes={ind['hashes']}")


def test_end_to_end_response_engine():
    """Full flow: detection → quarantine → persistence hunt → event +
    meta.json updated. Uses fake persistence roots + hash_sweep disabled."""
    section("6. End-to-end: quarantine triggers persistence hunt")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step3_e2e_"))
    payload = tmp / "payload_e2e.bin"
    payload.write_bytes(b"EVIL_E2E_CONTENT_xxxxxxxxxxxx")

    # Fake persistence root: cron file pointing to payload.
    fake_root = tmp / "fake_etc"
    cron_dir = fake_root / "cron.d"
    cron_dir.mkdir(parents=True)
    (cron_dir / "evil_persist").write_text(
        f"*/1 * * * * root {payload} --beacon\n"
    )

    bus = EventBus(db_path=str(tmp / "events.db"))
    engine = ResponseEngine(bus, {
        "auto_respond": True,
        "quarantine_dir": str(tmp / "q"),
        "forensics_dir": str(tmp / "f"),
        "severity_actions": {"high": ["quarantine_file"]},
        "hash_sweep": {"enabled": False},
        "persistence_hunt": {
            "enabled": True,
            "platform": "posix",
            "roots": {
                "cron": [str(cron_dir / "*")],
                "systemd": [],
                "profiles": [],
                "init": [],
                "ld_preload": [],
            },
        },
    })
    engine.start()

    events: list[Event] = []
    bus.subscribe("response.persistence", lambda e: events.append(e))

    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={
            "filepath": str(payload),
            "rule_name": "TestE2EPersist",
            "rule_id": "TEST-STEP3-001",
        },
    ))
    time.sleep(0.3)

    check(len(events) == 1, "one persistence event published",
          f"got {len(events)}")
    if events:
        e = events[0]
        check(e.data["action"] == "persistence_hunt_complete",
              "action = persistence_hunt_complete")
        check(e.data["hits_found"] == 1,
              "one hit found (the cron entry)",
              f"got {e.data['hits_found']}")
        check(e.severity == Severity.HIGH,
              "severity HIGH when hits present")
        hits = e.data["hits"]
        check(hits[0]["surface"] == "cron", "hit surface = cron")
        check(hits[0]["case_id"] == e.data["case_id"],
              "hit stamped with case_id")
        check("payload_e2e.bin" in hits[0]["reference"]
              or str(payload) in hits[0]["reference"],
              "reference contains the evil path",
              f"reference={hits[0]['reference']}")

    # meta.json contains persistence_hits[]
    metas = list((tmp / "q").glob("*.meta.json"))
    check(len(metas) == 1, "primary meta.json written")
    if metas:
        meta = json.loads(metas[0].read_text())
        check("persistence_hits" in meta,
              "meta.json has persistence_hits field")
        check(len(meta.get("persistence_hits", [])) == 1,
              "meta.json persistence_hits has 1 entry")

    engine.stop()
    bus.shutdown()


def test_persistence_disabled():
    """persistence_hunt.enabled=false ⇒ no persistence event published."""
    section("7. Disabled config ⇒ no persistence event")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_step3_off_"))
    payload = tmp / "payload.bin"
    payload.write_bytes(b"x" * 128)

    bus = EventBus(db_path=str(tmp / "events.db"))
    engine = ResponseEngine(bus, {
        "auto_respond": True,
        "quarantine_dir": str(tmp / "q"),
        "forensics_dir": str(tmp / "f"),
        "severity_actions": {"high": ["quarantine_file"]},
        "hash_sweep": {"enabled": False},
        "persistence_hunt": {"enabled": False},
    })
    engine.start()

    events: list[Event] = []
    bus.subscribe("response.persistence", lambda e: events.append(e))
    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={"filepath": str(payload), "rule_name": "T", "rule_id": "T"},
    ))
    time.sleep(0.2)
    check(len(events) == 0, "no persistence events when disabled",
          f"got {len(events)}")
    engine.stop()
    bus.shutdown()


if __name__ == "__main__":
    test_posix_surfaces()
    test_windows_surfaces_via_mocks()
    test_basename_min_length_guard()
    test_surface_isolation()
    test_build_indicators()
    test_end_to_end_response_engine()
    test_persistence_disabled()

    print("\n" + "=" * 55)
    if failures:
        print(f"RESULT: {len(failures)} failing check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("RESULT: all Step 3 persistence checks PASSED")
        sys.exit(0)
