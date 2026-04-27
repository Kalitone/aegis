"""
AEGIS — eBPF Process Monitor Test
==================================
Validates the Linux push-based process tracer (R&D backlog #7).

This test suite runs on every platform — including the Windows host
this project ships from. The bcc-dependent code paths are exercised
via stub injection since:

  * bcc Python bindings don't install on Windows / macOS.
  * Even on Linux, loading a real eBPF program requires CAP_BPF or
    root, which CI runners typically don't grant.

The pure functions (`map_kernel_event`, `_decode_argv`) and the
class-level integration (start/stop, event publication, soft-fail)
are covered. The actual kernel tracepoint and ring-buffer drain are
empirically validated only when a Linux operator runs AEGIS with
`monitors.proc_ebpf.enabled: true` on a real kernel.

Invariants:
  1. `_decode_argv` translates NUL-delimited argv into a space-joined
     string and tolerates bytes / bytearray / empty input.
  2. `map_kernel_event` produces the documented PROC_CREATE shape
     (pid/ppid/uid/gid/name/exe/cmdline/telemetry_source) and never
     raises on partial input.
  3. `EbpfProcessMonitor._is_supported_platform()` returns True only
     on Linux.
  4. `EbpfProcessMonitor.start()` with `enabled=False` is a clean
     no-op (no thread, no bus subscription).
  5. On non-Linux: `start()` flips `enabled=False`, never raises,
     never spawns a thread.
  6. On Linux with bcc missing: the soft-fail path triggers; engine
     stays disabled, AEGIS continues with the polling monitor.
  7. With a stub BPF object injected, `start()` reaches the
     ring-buffer registration call and the worker thread launches.
  8. `ingest_kernel_event` publishes a PROC_CREATE event with
     source="proc_ebpf" and the mapped data fields.
  9. `EBPF_C_PROGRAM` declares the documented hook
     (`TRACEPOINT_PROBE(sched, sched_process_exec)`) and the perf
     output table.
 10. The monitor's event_count increments per ingested kernel event.
"""
import platform
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.monitors.proc_ebpf import (
    EbpfProcessMonitor,
    EBPF_C_PROGRAM,
    map_kernel_event,
    _decode_argv,
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


# ── Pure helpers ────────────────────────────────────────────────────

def test_decode_argv():
    section("1. _decode_argv handles NUL-delimited bytes / bytearray / empty")
    cases = [
        (b"bash\x00-c\x00ls /tmp\x00", "bash -c ls /tmp"),
        (b"single\x00", "single"),
        (b"", ""),
        (bytearray(b"node\x00server.js\x00"), "node server.js"),
        # Kernel pads the tail with double-NUL — we should stop there
        (b"a\x00b\x00\x00\x00\x00", "a b"),
    ]
    for raw, expected in cases:
        out = _decode_argv(raw)
        check(out == expected,
              f"_decode_argv({raw!r}) == {expected!r}",
              f"got {out!r}")


def test_map_kernel_event_full():
    section("2. map_kernel_event produces the documented PROC_CREATE shape")
    evt = {
        "pid": 12345, "ppid": 1, "uid": 1000, "gid": 1000,
        "comm": b"bash\x00",
        "filename": b"/usr/bin/bash\x00",
        "argv": b"bash\x00-c\x00echo hi\x00",
        "ts_ns": 1234567890,
    }
    out = map_kernel_event(evt)
    check(out["pid"] == 12345, "pid carried")
    check(out["ppid"] == 1, "ppid carried")
    check(out["uid"] == 1000 and out["gid"] == 1000, "uid/gid carried")
    check(out["name"] == "bash",
          f"comm decoded to 'bash' (got {out['name']!r})")
    check(out["exe"] == "/usr/bin/bash",
          f"filename decoded (got {out['exe']!r})")
    check(out["cmdline"] == "bash -c echo hi",
          f"cmdline decoded (got {out['cmdline']!r})")
    check(out["telemetry_source"] == "ebpf.sched_process_exec",
          "telemetry_source label set")


def test_map_kernel_event_partial():
    section("3. map_kernel_event tolerates partial / empty input")
    out = map_kernel_event({})
    check(out["pid"] == 0, "pid defaults to 0")
    check(out["name"] == "" and out["exe"] == "" and out["cmdline"] == "",
          "string fields default to empty")
    check(out["telemetry_source"] == "ebpf.sched_process_exec",
          "telemetry_source still set")


def test_ebpf_program_text():
    section("4. EBPF_C_PROGRAM declares the documented hook + table")
    check("TRACEPOINT_PROBE(sched, sched_process_exec)" in EBPF_C_PROGRAM,
          "tracepoint probe declared")
    check("BPF_PERF_OUTPUT(exec_events)" in EBPF_C_PROGRAM,
          "perf output table declared")
    check("struct exec_event_t" in EBPF_C_PROGRAM,
          "event struct declared")


# ── Platform detection ─────────────────────────────────────────────

def test_platform_detect():
    section("5. _is_supported_platform reflects host OS")
    expected = platform.system().lower() == "linux"
    check(EbpfProcessMonitor._is_supported_platform() is expected,
          f"_is_supported_platform() == {expected} on this host")


def test_disabled_is_noop():
    section("6. enabled=False is a clean no-op (no thread, no subscribe)")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ebpf_off_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    mon = EbpfProcessMonitor(bus, {"enabled": False})
    mon.start()
    check(mon.is_running is False, "is_running stays False")
    check(mon._thread is None, "no worker thread spawned")
    mon.stop()
    check(True, "stop() did not raise")


def test_non_linux_soft_fails():
    section("7. Non-Linux soft-fails: start() flips enabled=False, no raise")
    # We force the platform check to return False so this test runs
    # the same way on Linux CI as on this Windows dev host.
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ebpf_xnix_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    mon = EbpfProcessMonitor(bus, {"enabled": True})
    original = EbpfProcessMonitor._is_supported_platform
    EbpfProcessMonitor._is_supported_platform = staticmethod(lambda: False)
    try:
        mon.start()
    finally:
        EbpfProcessMonitor._is_supported_platform = staticmethod(original)
    check(mon.enabled is False,
          "start() flipped enabled=False on unsupported platform")
    check(mon.is_running is False, "no thread spawned")


def test_bcc_missing_soft_fails():
    section("8. bcc import failure soft-fails the monitor")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ebpf_nobcc_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    mon = EbpfProcessMonitor(bus, {"enabled": True})
    # Force "supported platform" but make _build_bpf raise.
    original = EbpfProcessMonitor._is_supported_platform
    EbpfProcessMonitor._is_supported_platform = staticmethod(lambda: True)
    mon._build_bpf = lambda: (_ for _ in ()).throw(
        ImportError("bcc not installed (test simulation)")
    )
    try:
        mon.start()
    finally:
        EbpfProcessMonitor._is_supported_platform = staticmethod(original)
    check(mon.enabled is False,
          "bcc-missing flips enabled=False")
    check(mon.is_running is False,
          "no worker thread on bcc-missing path")


# ── Stub-BPF integration ───────────────────────────────────────────

class _StubPerfTable:
    """Stand-in for `bpf['exec_events']`."""
    def __init__(self):
        self.opened = False
        self.cb = None

    def open_perf_buffer(self, callback, page_cnt=64):
        self.opened = True
        self.cb = callback


class _StubBPF:
    """Mimics enough of `bcc.BPF` for `EbpfProcessMonitor.start()` +
    the worker loop. `perf_buffer_poll` returns immediately so the
    daemon thread doesn't block the test."""

    def __init__(self):
        self._tables = {"exec_events": _StubPerfTable()}
        self.poll_calls = 0
        self.cleaned = False

    def __getitem__(self, key):
        return self._tables[key]

    def perf_buffer_poll(self, timeout=100):
        self.poll_calls += 1
        # Return promptly so the worker loop doesn't pin the test.
        time.sleep(0.01)

    def cleanup(self):
        self.cleaned = True


def test_stub_bpf_lifecycle():
    section("9. Stub BPF: start opens perf-buffer + spawns worker; stop cleans up")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ebpf_stub_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    stub = _StubBPF()
    mon = EbpfProcessMonitor(bus, {
        "enabled": True,
        "_bpf_override": stub,
    })
    # Force "supported" so the start path doesn't bail on Windows.
    original = EbpfProcessMonitor._is_supported_platform
    EbpfProcessMonitor._is_supported_platform = staticmethod(lambda: True)
    try:
        mon.start()
    finally:
        EbpfProcessMonitor._is_supported_platform = staticmethod(original)

    check(stub["exec_events"].opened is True,
          "open_perf_buffer was called on the perf table")
    check(mon.is_running is True, "is_running True after start")
    check(mon._thread is not None, "worker thread spawned")
    # Let the worker poll at least once
    time.sleep(0.15)
    check(stub.poll_calls >= 1,
          f"perf_buffer_poll called at least once (got {stub.poll_calls})")
    mon.stop()
    check(stub.cleaned is True, "BPF.cleanup() called on stop")
    check(mon.is_running is False, "is_running False after stop")


def test_ingest_publishes_proc_create():
    section("10. ingest_kernel_event publishes PROC_CREATE with mapped data")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_ebpf_pub_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    mon = EbpfProcessMonitor(bus, {"enabled": False})  # bypass start()
    captured: list[Event] = []
    bus.subscribe("proc.create", lambda e: captured.append(e))

    mon.ingest_kernel_event({
        "pid": 4242, "ppid": 1, "uid": 0, "gid": 0,
        "comm": b"sshd\x00",
        "filename": b"/usr/sbin/sshd\x00",
        "argv": b"sshd\x00-D\x00",
        "ts_ns": 99,
    })
    check(len(captured) == 1, f"one event published (got {len(captured)})")
    if captured:
        ev = captured[0]
        check(ev.category == EventCategory.PROC_CREATE,
              "category is PROC_CREATE")
        check(ev.source == "proc_ebpf", "source labelled 'proc_ebpf'")
        check(ev.severity == Severity.INFO, "severity INFO")
        check(ev.data.get("pid") == 4242, "pid in data")
        check(ev.data.get("name") == "sshd", "name decoded")
        check(ev.data.get("cmdline") == "sshd -D", "cmdline decoded")
        check(ev.data.get("telemetry_source") == "ebpf.sched_process_exec",
              "telemetry_source preserved on bus")
    check(mon.event_count == 1,
          f"event_count incremented (got {mon.event_count})")


def main():
    print("=" * 60)
    print("AEGIS — eBPF Process Monitor Test")
    print(f"(Host: {platform.system()} — bcc-dependent paths run via stubs)")
    print("=" * 60)

    test_decode_argv()
    test_map_kernel_event_full()
    test_map_kernel_event_partial()
    test_ebpf_program_text()
    test_platform_detect()
    test_disabled_is_noop()
    test_non_linux_soft_fails()
    test_bcc_missing_soft_fails()
    test_stub_bpf_lifecycle()
    test_ingest_publishes_proc_create()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
