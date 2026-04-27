"""
AEGIS — Quarantine Allow-List Test
==================================
Validates the pre-flight gate added in response to a real false-positive
incident: a YARA `credential_harvester` rule matched the live Microsoft
OneAuth token store and the engine quarantined it, breaking SSO until
the file was restored. The allow-list refuses to quarantine canonical
credential / browser / mailbox paths even when a high-severity rule
fires against them.

Invariants:
  1. Allow-list helper recognises every default Windows / Linux / macOS
     canonical path; case + slash variation does not bypass it.
  2. Files outside the allow-list still quarantine normally.
  3. A file matching the allow-list is NOT moved, NOT hashed, NOT
     written to quarantine; instead a `quarantine_blocked` event fires.
  4. Operator-supplied `quarantine.allow_list_paths` are honoured on
     top of the defaults.
  5. The block event carries case_id + allow_list_match label so the
     dashboard / audit trail can show *why* it was refused.
"""
import os
import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.response import (
    ResponseEngine,
    _is_quarantine_allowed,
    _DEFAULT_QUARANTINE_ALLOW_SUBSTRINGS,
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


def _make_engine(tmp: Path, **extra) -> tuple[EventBus, ResponseEngine]:
    bus = EventBus(db_path=str(tmp / "events.db"))
    cfg = {
        "auto_respond": True,
        "quarantine_dir": str(tmp / "q"),
        "forensics_dir": str(tmp / "f"),
        "severity_actions": {"high": ["quarantine_file"]},
        "hash_sweep": {"enabled": False},
        "persistence_hunt": {"enabled": False},
        "hardening_recheck": {"enabled": False},
    }
    cfg.update(extra)
    engine = ResponseEngine(bus, cfg)
    engine.start()
    return bus, engine


def test_helper_recognises_defaults():
    section("1. _is_quarantine_allowed: default canonical paths")

    cases = [
        # (path, expected_match_truthy)
        (r"C:\Users\alice\AppData\Local\Microsoft\OneAuth\msalcache.bin", True),
        (r"C:\Users\alice\AppData\Local\Microsoft\TokenBroker\Cache\x.dat", True),
        (r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Cookies", True),
        (r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data", True),
        (r"C:\Users\alice\OneDrive\Documents\report.docx", True),
        (r"C:\Users\alice\Documents\Outlook Files\archive.pst", True),
        (r"C:\Users\alice\AppData\Local\Microsoft\Outlook\inbox.ost", True),
        ("/home/bob/.ssh/id_rsa", True),
        ("/home/bob/.config/google-chrome/Default/Cookies", True),
        ("/Users/carol/Library/Keychains/login.keychain-db", True),
        # Non-protected
        (r"C:\Users\alice\Downloads\suspicious.exe", False),
        ("/tmp/dropper.bin", False),
        ("/usr/local/bin/xmrig", False),
    ]
    for path, expected in cases:
        match = _is_quarantine_allowed(path)
        ok = (match is not None) == expected
        check(ok, f"{'protected' if expected else 'not protected'}: {path}",
              f"match={match}")


def test_helper_case_and_slash_insensitive():
    section("2. Case + slash insensitivity")

    # Mixed case, forward slashes, weird drive letter — all must match.
    weird = "D:/Users/Alice/AppData/Local/MICROSOFT/OneAuth/foo.bin"
    check(_is_quarantine_allowed(weird) is not None,
          "mixed-case + forward-slash OneAuth path matched")

    # Substring must not match if it's elsewhere by accident.
    benign = r"C:\Tools\notmicrosoft\notoneauth\file.exe"
    check(_is_quarantine_allowed(benign) is None,
          "substring not in canonical context: not blocked")


def test_helper_extras():
    section("3. Operator-supplied extras")

    extra = ("\\\\fileserver\\creds\\", "/opt/secret/")
    check(_is_quarantine_allowed(
        r"\\fileserver\creds\db.sqlite", extra_substrings=extra
    ) is not None, "Windows UNC extra path matched")
    check(_is_quarantine_allowed(
        "/opt/secret/notes.txt", extra_substrings=extra
    ) is not None, "Linux extra path matched")
    check(_is_quarantine_allowed(
        "/var/log/syslog", extra_substrings=extra
    ) is None, "non-extra path not blocked")


def test_engine_blocks_oneauth():
    section("4. ResponseEngine: OneAuth path is blocked, event published")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_qal_oneauth_"))
    # Simulate an OneAuth-shaped path. The substring match fires on the
    # path string AEGIS receives in event.data["filepath"]; we don't need
    # the path to actually live under %LOCALAPPDATA%.
    fake_root = tmp / "AppData" / "Local" / "Microsoft" / "OneAuth"
    fake_root.mkdir(parents=True)
    target = fake_root / "msalcache.bin"
    target.write_bytes(b"FAKE_TOKEN_BLOB" * 64)

    bus, engine = _make_engine(tmp)
    captured: list[Event] = []
    bus.subscribe("response.quarantine", lambda e: captured.append(e))

    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={
            "filepath": str(target),
            "rule_name": "credential_harvester",
            "rule_id": "credential_harvester",
        },
    ))
    time.sleep(0.1)

    blocked = [e for e in captured
               if e.data.get("action") == "quarantine_blocked"]
    quarantined = [e for e in captured
                   if e.data.get("action") == "file_quarantined"]

    check(len(blocked) == 1,
          "exactly one quarantine_blocked event fired",
          f"got {len(blocked)} blocked, {len(quarantined)} quarantined")
    check(len(quarantined) == 0,
          "NO file_quarantined event fired for protected path")
    check(target.exists(),
          "live OneAuth file still in place (not moved to quarantine)")
    if blocked:
        ev = blocked[0]
        check("oneauth" in (ev.data.get("allow_list_match") or "").lower(),
              "block event labelled with the matching rule",
              f"label={ev.data.get('allow_list_match')}")
        check(ev.data.get("rule_id") == "credential_harvester",
              "block event preserves the original rule_id")


def test_engine_quarantines_normal_path():
    section("5. ResponseEngine: ordinary path still quarantines")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_qal_normal_"))
    target = tmp / "downloads" / "dropper.bin"
    target.parent.mkdir()
    target.write_bytes(b"EVIL_PAYLOAD" * 32)

    bus, engine = _make_engine(tmp)
    captured: list[Event] = []
    bus.subscribe("response.quarantine", lambda e: captured.append(e))

    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={"filepath": str(target),
              "rule_name": "evil_dropper",
              "rule_id": "evil_dropper"},
    ))
    time.sleep(0.1)

    quarantined = [e for e in captured
                   if e.data.get("action") == "file_quarantined"
                   and not e.data.get("parent_case_id")]
    blocked = [e for e in captured
               if e.data.get("action") == "quarantine_blocked"]

    check(len(quarantined) == 1,
          "exactly one file_quarantined event fired",
          f"got {len(quarantined)} quarantined, {len(blocked)} blocked")
    check(not target.exists(),
          "original file moved out (quarantined)")


def test_engine_extra_config():
    section("6. Operator-extended allow-list via config")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_qal_extra_"))
    secret_root = tmp / "company-secret"
    secret_root.mkdir()
    target = secret_root / "license.dat"
    target.write_bytes(b"LICENSE_BLOB" * 16)

    bus, engine = _make_engine(
        tmp,
        quarantine={"allow_list_paths": [str(secret_root)]},
    )
    captured: list[Event] = []
    bus.subscribe("response.quarantine", lambda e: captured.append(e))

    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={"filepath": str(target),
              "rule_name": "fp_rule",
              "rule_id": "fp_rule"},
    ))
    time.sleep(0.1)

    blocked = [e for e in captured
               if e.data.get("action") == "quarantine_blocked"]
    check(len(blocked) == 1, "operator-extended path blocked")
    check(target.exists(), "operator-protected file untouched")


def main():
    print("=" * 60)
    print("AEGIS — Quarantine Allow-List Test")
    print("=" * 60)

    test_helper_recognises_defaults()
    test_helper_case_and_slash_insensitive()
    test_helper_extras()
    test_engine_blocks_oneauth()
    test_engine_quarantines_normal_path()
    test_engine_extra_config()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
