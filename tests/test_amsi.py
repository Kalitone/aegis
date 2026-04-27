"""
AEGIS — AMSI Client + Scanner Test
===================================
Validates the Windows Antimalware Scan Interface client (R&D #4).
Every test that exercises the real `amsi.dll` is gated on
`AmsiClient().open()` succeeding — Linux / macOS / Windows builds
without AMSI auto-skip those checks but still exercise the
mock-backed scanner integration tests.

Invariants:
  1. `AmsiClient.open()` returns False on non-Windows; True on
     Windows when amsi.dll loads + AmsiInitialize succeeds.
  2. EICAR string → result ≥ 32768 (`AMSI_RESULT_DETECTED`),
     `is_malware` True. This is the industry-standard health probe;
     if it fails, Defender (or the active provider) is broken on
     this host.
  3. Benign cmdlet (`Get-Date`) → result < 32768, `is_malware` False.
  4. Empty buffer → handled, `is_malware` False.
  5. After `close()`, `available` is False and further scans
     return `available=False`.
  6. _is_malware threshold: 32767 → False, 32768 → True.
  7. `AmsiScanner` with a stub client publishes a `detection.amsi`
     event on a malware verdict from a `file.create` event.
  8. `AmsiScanner` ignores files whose extension isn't in the
     allow-list (no event published, no scan attempted).
  9. `AmsiScanner` enforces `max_file_size_mb` — oversized files
     are skipped silently.
 10. `publish_clean_results=False` (default) suppresses INFO-level
     events for clean scans.
 11. `publish_clean_results=True` produces an INFO event per clean
     scan.
 12. Events carry MITRE T1059 (Command and Scripting Interpreter).
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.detection.amsi import (
    AmsiClient,
    AmsiScanner,
    AMSI_RESULT_DETECTED,
    AMSI_RESULT_NOT_DETECTED,
    EICAR_TEST_STRING,
    _is_malware,
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


# ── Real AMSI client (skipped where unavailable) ────────────────────

_client_for_real_tests: AmsiClient | None = None


def _real_client() -> AmsiClient | None:
    """Lazy-init a single client for the AMSI-live tests."""
    global _client_for_real_tests
    if _client_for_real_tests is not None:
        return _client_for_real_tests
    c = AmsiClient(app_name="AEGIS-TEST")
    if not c.open():
        return None
    _client_for_real_tests = c
    return c


def test_real_eicar_detected():
    section("1. Real AMSI: EICAR string is flagged as malware")
    c = _real_client()
    if c is None:
        print("  [skip] AMSI not available on this host")
        return
    r = c.scan_buffer(EICAR_TEST_STRING.encode("ascii"), "eicar.txt")
    check(r["available"] is True, "available=True")
    check(r["is_malware"] is True,
          f"is_malware=True (got result={r['result']})")
    check(r["result"] >= AMSI_RESULT_DETECTED,
          f"result >= AMSI_RESULT_DETECTED ({AMSI_RESULT_DETECTED}) "
          f"(got {r['result']})")


def test_real_benign_not_flagged():
    section("2. Real AMSI: benign PowerShell cmdlet not flagged")
    c = _real_client()
    if c is None:
        print("  [skip] AMSI not available on this host")
        return
    r = c.scan_buffer(b"Get-Date", "benign.ps1")
    check(r["available"] is True, "available=True")
    check(r["is_malware"] is False,
          f"is_malware=False (got result={r['result']})")


def test_real_empty_buffer():
    section("3. Real AMSI: empty buffer scans cleanly")
    c = _real_client()
    if c is None:
        print("  [skip] AMSI not available on this host")
        return
    r = c.scan_buffer(b"", "empty")
    check(r["available"] is True, "available=True")
    check(r["is_malware"] is False, "empty buffer → is_malware=False")


def test_real_close_disables():
    section("4. Real AMSI: close() disables further scans")
    c = AmsiClient(app_name="AEGIS-TEST-CLOSE")
    if not c.open():
        print("  [skip] AMSI not available on this host")
        return
    check(c.available is True, "open() set available=True")
    c.close()
    check(c.available is False, "close() set available=False")
    r = c.scan_buffer(EICAR_TEST_STRING.encode("ascii"), "post-close")
    check(r["available"] is False,
          "post-close scan returns available=False")


# ── Threshold helper ────────────────────────────────────────────────

def test_is_malware_threshold():
    section("5. _is_malware boundary at 32768")
    check(_is_malware(0) is False, "0 → False")
    check(_is_malware(1) is False, "1 (NOT_DETECTED) → False")
    check(_is_malware(32767) is False, "32767 → False (just under)")
    check(_is_malware(32768) is True, "32768 → True (boundary)")
    check(_is_malware(32769) is True, "32769 → True")


# ── Stub-backed scanner integration ─────────────────────────────────

class _StubClient:
    """Test stand-in for AmsiClient. Returns whatever response is
    queued in `_results` keyed off filename or default."""

    available = True

    def __init__(self, default_result: int = AMSI_RESULT_NOT_DETECTED):
        self._default = default_result
        self._results: dict[str, int] = {}
        self.calls: list[tuple[str, int]] = []   # (path, len(buf))

    def queue(self, path: str, result: int):
        self._results[path] = result

    def open(self) -> bool:
        return True

    def close(self):
        pass

    def scan_buffer(self, buf: bytes, content_name: str = "") -> dict:
        self.calls.append((content_name, len(buf)))
        r = self._results.get(content_name, self._default)
        return {
            "available": True,
            "result": r,
            "is_malware": _is_malware(r),
            "is_blocked_admin": False,
            "name": content_name,
        }


def _make_scanner(tmp: Path, *, stub: _StubClient,
                  publish_clean: bool = False,
                  max_mb: int = 16,
                  extensions=None) -> tuple[EventBus, AmsiScanner, list[Event]]:
    bus = EventBus(db_path=str(tmp / "events.db"))
    scanner = AmsiScanner(bus, {
        "enabled": True,
        "max_file_size_mb": max_mb,
        "publish_clean_results": publish_clean,
        "extensions": extensions or [".ps1", ".vbs", ".js"],
        "client": stub,
    })
    captured: list[Event] = []
    bus.subscribe("detection.amsi", lambda e: captured.append(e))
    scanner.start()
    return bus, scanner, captured


def test_scanner_publishes_on_malware():
    section("6. Scanner publishes detection.amsi on malware verdict")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_amsi_mw_"))
    target = tmp / "evil.ps1"
    target.write_text("Invoke-Mimikatz", encoding="utf-8")

    stub = _StubClient(default_result=AMSI_RESULT_NOT_DETECTED)
    stub.queue(str(target), AMSI_RESULT_DETECTED)

    bus, scanner, captured = _make_scanner(tmp, stub=stub)
    try:
        bus.publish(Event(
            category=EventCategory.FILE_CREATE,
            severity=Severity.INFO,
            source="fim",
            data={"path": str(target)},
        ))
    finally:
        scanner.stop()

    matches = [e for e in captured if e.data.get("rule_id") == "AMSI-MALWARE"]
    check(len(matches) == 1, f"one AMSI-MALWARE event (got {len(matches)})")
    if matches:
        ev = matches[0]
        check(ev.severity == Severity.HIGH, "severity HIGH on malware")
        check(ev.category == EventCategory.DETECTION_AMSI,
              "category is DETECTION_AMSI")
        check(ev.mitre_attack == "T1059",
              f"MITRE T1059 stamped (got {ev.mitre_attack})")
        check(ev.data.get("filepath") == str(target),
              "filepath in data")
        check(len(ev.data.get("sha256") or "") == 64,
              "sha256 captured")


def test_scanner_skips_non_script_extensions():
    section("7. Scanner ignores non-script extensions (no scan, no event)")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_amsi_ext_"))
    target = tmp / "movie.mp4"
    target.write_bytes(b"\x00" * 1024)

    stub = _StubClient(default_result=AMSI_RESULT_DETECTED)  # would flag
    bus, scanner, captured = _make_scanner(tmp, stub=stub)
    try:
        bus.publish(Event(
            category=EventCategory.FILE_CREATE, severity=Severity.INFO,
            source="fim", data={"path": str(target)},
        ))
    finally:
        scanner.stop()

    check(captured == [], "no events for non-script extension")
    # Stub.calls includes the EICAR start-up probe. Filter to scans
    # of `target` specifically.
    target_calls = [c for c in stub.calls if c[0] == str(target)]
    check(target_calls == [],
          f"AmsiClient.scan_buffer NOT called for non-script "
          f"(got {target_calls})")


def test_scanner_enforces_size_limit():
    section("8. Scanner skips files over max_file_size_mb")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_amsi_size_"))
    target = tmp / "big.ps1"
    # 2 MB file — over the 1 MB cap we'll set
    target.write_bytes(b"A" * (2 * 1024 * 1024))

    stub = _StubClient(default_result=AMSI_RESULT_DETECTED)
    bus, scanner, captured = _make_scanner(tmp, stub=stub, max_mb=1)
    try:
        bus.publish(Event(
            category=EventCategory.FILE_CREATE, severity=Severity.INFO,
            source="fim", data={"path": str(target)},
        ))
    finally:
        scanner.stop()

    check(captured == [], "no event for oversized file")
    target_calls = [c for c in stub.calls if c[0] == str(target)]
    check(target_calls == [],
          f"oversized file never reaches AmsiClient (got {target_calls})")


def test_scanner_publish_clean_off_by_default():
    section("9. Clean-result publication off by default")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_amsi_clean_off_"))
    target = tmp / "ok.ps1"
    target.write_text("Get-Date", encoding="utf-8")

    stub = _StubClient(default_result=AMSI_RESULT_NOT_DETECTED)
    bus, scanner, captured = _make_scanner(tmp, stub=stub,
                                           publish_clean=False)
    try:
        bus.publish(Event(
            category=EventCategory.FILE_CREATE, severity=Severity.INFO,
            source="fim", data={"path": str(target)},
        ))
    finally:
        scanner.stop()
    check(captured == [], "no event published when scan is clean (default)")


def test_scanner_publish_clean_when_enabled():
    section("10. publish_clean_results=True emits INFO event for clean scans")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_amsi_clean_on_"))
    target = tmp / "ok.ps1"
    target.write_text("Get-Date", encoding="utf-8")

    stub = _StubClient(default_result=AMSI_RESULT_NOT_DETECTED)
    bus, scanner, captured = _make_scanner(tmp, stub=stub,
                                           publish_clean=True)
    try:
        bus.publish(Event(
            category=EventCategory.FILE_CREATE, severity=Severity.INFO,
            source="fim", data={"path": str(target)},
        ))
    finally:
        scanner.stop()

    matches = [e for e in captured if e.data.get("rule_id") == "AMSI-CLEAN"]
    check(len(matches) == 1, f"one AMSI-CLEAN event (got {len(matches)})")
    if matches:
        check(matches[0].severity == Severity.INFO,
              "clean scan severity INFO")


def test_scanner_handles_admin_block():
    section("11. Admin policy block → MEDIUM severity AMSI-ADMIN-BLOCK event")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_amsi_admin_"))
    target = tmp / "policy.ps1"
    target.write_text("Some-Cmdlet", encoding="utf-8")

    stub = _StubClient(default_result=AMSI_RESULT_NOT_DETECTED)
    stub.queue(str(target), 16384)   # AMSI_RESULT_BLOCKED_BY_ADMIN_START
    # Admin-block range: 16384..20479. is_malware False. is_blocked_admin True.

    # Manually plumb the queued result; default stub doesn't set is_blocked_admin
    class _AdminStub(_StubClient):
        def scan_buffer(self, buf, content_name=""):
            self.calls.append((content_name, len(buf)))
            r = self._results.get(content_name, self._default)
            return {
                "available": True, "result": r,
                "is_malware": _is_malware(r),
                "is_blocked_admin": (16384 <= r <= 20479),
                "name": content_name,
            }

    admin_stub = _AdminStub(default_result=AMSI_RESULT_NOT_DETECTED)
    admin_stub.queue(str(target), 16384)
    bus, scanner, captured = _make_scanner(tmp, stub=admin_stub)
    try:
        bus.publish(Event(
            category=EventCategory.FILE_CREATE, severity=Severity.INFO,
            source="fim", data={"path": str(target)},
        ))
    finally:
        scanner.stop()

    matches = [e for e in captured
               if e.data.get("rule_id") == "AMSI-ADMIN-BLOCK"]
    check(len(matches) == 1,
          f"one AMSI-ADMIN-BLOCK event (got {len(matches)})")
    if matches:
        check(matches[0].severity == Severity.MEDIUM,
              "admin-block severity MEDIUM")


def test_scanner_disabled_is_noop():
    section("12. Scanner with enabled=false starts cleanly without subscribing")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_amsi_off_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    scanner = AmsiScanner(bus, {"enabled": False})
    scanner.start()
    scanner.stop()
    check(True, "start/stop on disabled config did not raise")


def main():
    print("=" * 60)
    print("AEGIS — AMSI Client + Scanner Test")
    print("=" * 60)

    test_real_eicar_detected()
    test_real_benign_not_flagged()
    test_real_empty_buffer()
    test_real_close_disables()
    test_is_malware_threshold()
    test_scanner_publishes_on_malware()
    test_scanner_skips_non_script_extensions()
    test_scanner_enforces_size_limit()
    test_scanner_publish_clean_off_by_default()
    test_scanner_publish_clean_when_enabled()
    test_scanner_handles_admin_block()
    test_scanner_disabled_is_noop()

    # Drop the cached real client so subsequent test runs don't hit
    # a stale handle.
    global _client_for_real_tests
    if _client_for_real_tests is not None:
        _client_for_real_tests.close()
        _client_for_real_tests = None

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
