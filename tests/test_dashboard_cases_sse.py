"""
AEGIS — Dashboard Cases View + SSE Test
========================================
Validates the two pieces of the dashboard upgrade:
  * EventBus.list_cases / query_case_events — case-rollup queries
    used by the cases pages.
  * /cases and /cases/{id} HTML pages render cleanly off real bus
    state.
  * /api/events/stream SSE endpoint pushes rows as events publish,
    cleans up its bus subscription when the client disconnects, and
    survives an event burst without dropping the connection.

We use FastAPI's TestClient (httpx-backed). Each test owns a fresh
in-memory bus so subscriptions don't leak across cases.

Invariants:
  1. list_cases groups events by `case_id` extracted from data.
  2. list_cases also finds case_ids nested under `data.case.case_id`
     (response engine's quarantine event shape).
  3. Highest severity across a case wins the rollup.
  4. query_case_events returns events oldest-first and only those
     referencing the case.
  5. /cases renders with the case row visible.
  6. /cases/{id} renders the timeline.
  7. /cases/{unknown} renders a "no events" message instead of 404.
  8. /api/events/stream sets Content-Type: text/event-stream.
  9. /api/events/stream emits initial `retry:` + `: connected`
     frames and then a `data:` frame for each published event.
 10. After client disconnect, the SSE handler unsubscribes from the
     bus (the `*` pattern's subscriber list shrinks back).
 11. Live page HTML loads, contains the SSE bootstrap script, and
     references /api/events/stream — confirming the polling JS got
     swapped out.
"""
import socket
import sys
import time
import tempfile
import threading
import contextlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import uvicorn
from fastapi.testclient import TestClient

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.dashboard.web import create_app


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


def _make_bus(tmp: Path) -> EventBus:
    return EventBus(db_path=str(tmp / "events.db"))


def _make_app(bus: EventBus):
    full_cfg = {"core": {}, "dashboard_web": {"enabled": True}}
    return create_app(bus, full_cfg, aegis_ref=None)


def _free_port() -> int:
    """Pick an unused TCP port — avoid hard-coding so parallel runs
    of this test don't collide."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def _live_server(bus: EventBus):
    """Spawn a real uvicorn against the dashboard app on 127.0.0.1.

    TestClient streams SSE responses through an in-process transport
    that buffers in a way that hangs the SSE generator; a real server
    + a real `httpx.Client.stream()` mirrors what the browser does
    and uncovers the same code paths the production live page hits.
    """
    port = _free_port()
    app = _make_app(bus)
    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True,
                              name="aegis-dash-test-uvicorn")
    thread.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            httpx.get(base + "/", timeout=1.0)
            break
        except Exception:
            time.sleep(0.05)
    else:
        server.should_exit = True
        thread.join(timeout=2.0)
        raise RuntimeError(f"uvicorn did not come up on {base}")
    try:
        yield base
    finally:
        server.should_exit = True
        thread.join(timeout=2.0)


def _emit(bus: EventBus, **kw):
    """Convenience event publisher with sensible defaults."""
    bus.publish(Event(
        category=kw.pop("category", EventCategory.DETECTION_YARA),
        severity=kw.pop("severity", Severity.HIGH),
        source=kw.pop("source", "test"),
        data=kw.pop("data", {}),
        timestamp=kw.pop("timestamp", time.time()),
        mitre_attack=kw.pop("mitre_attack", ""),
    ))


# ── EventBus.list_cases / query_case_events ─────────────────────────

def test_list_cases_basic():
    section("1. list_cases groups events by case_id")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_lc_"))
    bus = _make_bus(tmp)

    _emit(bus, severity=Severity.MEDIUM,
          data={"case_id": "alpha", "rule_name": "evil",
                "filepath": r"C:\bad.exe"})
    _emit(bus, severity=Severity.HIGH,
          data={"case_id": "alpha", "rule_name": "evil"})
    _emit(bus, severity=Severity.LOW,
          data={"case_id": "beta", "rule_name": "milder"})
    # Event with no case_id — must NOT create a phantom case row.
    _emit(bus, data={"rule_name": "noisy"})

    cases = bus.list_cases(limit=10)
    by_id = {c["case_id"]: c for c in cases}
    check(set(by_id.keys()) == {"alpha", "beta"},
          f"two cases discovered (got {set(by_id.keys())})")
    if "alpha" in by_id:
        check(by_id["alpha"]["events"] == 2,
              f"alpha event count == 2 (got {by_id['alpha']['events']})")
        check(by_id["alpha"]["highest_severity"] == "high",
              "alpha highest_severity rolls up to 'high'")
        check(by_id["alpha"]["original_path"] == r"C:\bad.exe",
              "alpha original_path picked up from first event")


def test_list_cases_nested_case_id():
    section("2. list_cases finds case_id nested under data.case (response shape)")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_nest_"))
    bus = _make_bus(tmp)

    # Response engine publishes sibling-quarantine events with case_id
    # tucked under data.case (see response/__init__.py line ~499).
    _emit(bus, category=EventCategory.RESPONSE_QUARANTINE,
          severity=Severity.HIGH, source="response",
          data={"action": "file_quarantined",
                "case": {"case_id": "gamma", "parent_case_id": None},
                "original_path": r"C:\sibling.bin"})

    cases = bus.list_cases(limit=10)
    check(any(c["case_id"] == "gamma" for c in cases),
          "case_id discovered from nested data.case.case_id")


def test_list_cases_window():
    section("3. list_cases honours `since` window")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_win_"))
    bus = _make_bus(tmp)

    now = time.time()
    _emit(bus, data={"case_id": "old"}, timestamp=now - 7200)    # 2h ago
    _emit(bus, data={"case_id": "new"}, timestamp=now - 60)      # 1m ago

    cases = bus.list_cases(since=now - 600, limit=10)             # last 10m
    case_ids = {c["case_id"] for c in cases}
    check(case_ids == {"new"},
          f"only the recent case visible (got {case_ids})")


def test_query_case_events_ordering():
    section("4. query_case_events returns oldest-first and case-scoped")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_qce_"))
    bus = _make_bus(tmp)

    now = time.time()
    _emit(bus, severity=Severity.HIGH,
          data={"case_id": "k1", "rule_name": "a"}, timestamp=now - 10)
    _emit(bus, severity=Severity.HIGH,
          data={"case_id": "k1", "rule_name": "b"}, timestamp=now - 5)
    _emit(bus, severity=Severity.LOW,
          data={"case_id": "k2", "rule_name": "z"}, timestamp=now - 3)

    rows = bus.query_case_events("k1", limit=100)
    check(len(rows) == 2, f"2 events for k1 (got {len(rows)})")
    if len(rows) == 2:
        check(rows[0]["timestamp"] < rows[1]["timestamp"],
              "oldest-first ordering")
    other = bus.query_case_events("k2", limit=100)
    check(len(other) == 1, "k2 isolated from k1")


# ── /cases and /cases/{id} pages ────────────────────────────────────

def test_cases_page_renders():
    section("5. /cases renders rollup with the case row visible")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_cp_"))
    bus = _make_bus(tmp)

    _emit(bus, severity=Severity.HIGH,
          data={"case_id": "showme", "rule_name": "evil_dropper",
                "filepath": r"C:\evil\dropper.exe"},
          mitre_attack="T1059")

    client = TestClient(_make_app(bus))
    r = client.get("/cases")
    check(r.status_code == 200, f"HTTP 200 (got {r.status_code})")
    check("showme" in r.text,
          "case_id rendered on the page")
    check("evil_dropper" in r.text,
          "rule_name rendered on the page")
    check("/cases/showme" in r.text,
          "row links to the case detail page")


def test_case_detail_renders():
    section("6. /cases/{id} renders the event timeline")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_cd_"))
    bus = _make_bus(tmp)

    now = time.time()
    _emit(bus, severity=Severity.MEDIUM,
          data={"case_id": "tl", "rule_name": "first"},
          timestamp=now - 10)
    _emit(bus, severity=Severity.HIGH,
          data={"case_id": "tl", "rule_name": "second"},
          timestamp=now)

    client = TestClient(_make_app(bus))
    r = client.get("/cases/tl")
    check(r.status_code == 200, f"HTTP 200 (got {r.status_code})")
    check("Case · tl" in r.text, "header carries case id")
    check("first" in r.text and "second" in r.text,
          "both events appear in the timeline")
    # First event mentioned BEFORE second (oldest-first ordering)
    idx_first = r.text.find("first")
    idx_second = r.text.find("second")
    check(0 <= idx_first < idx_second,
          "oldest event appears first in HTML")


def test_case_detail_unknown():
    section("7. /cases/{unknown} renders empty-state, not 404")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_cdu_"))
    bus = _make_bus(tmp)
    client = TestClient(_make_app(bus))
    r = client.get("/cases/does-not-exist")
    check(r.status_code == 200, f"HTTP 200 (got {r.status_code})")
    check("No events found" in r.text, "empty-state message present")


# ── /api/events/stream SSE endpoint ────────────────────────────────

def test_sse_content_type_and_initial_frames():
    section("8. SSE endpoint sets Content-Type + emits init frames")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_sse_init_"))
    bus = _make_bus(tmp)

    with _live_server(bus) as base:
        with httpx.stream("GET", base + "/api/events/stream",
                          timeout=5.0) as r:
            check(r.status_code == 200, f"HTTP 200 (got {r.status_code})")
            ctype = r.headers.get("content-type", "")
            check("text/event-stream" in ctype,
                  f"Content-Type is text/event-stream (got {ctype!r})")

            chunks: list[bytes] = []
            deadline = time.time() + 4.0
            for chunk in r.iter_bytes():
                chunks.append(chunk)
                blob = b"".join(chunks).decode("utf-8", errors="replace")
                if "retry:" in blob and ": connected" in blob:
                    break
                if time.time() > deadline:
                    break
            blob = b"".join(chunks).decode("utf-8", errors="replace")
            check("retry:" in blob, "initial `retry:` frame received")
            check(": connected" in blob,
                  "initial `: connected` comment frame received")


def test_sse_pushes_published_event():
    section("9. SSE endpoint pushes a frame per published event")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_sse_push_"))
    bus = _make_bus(tmp)

    with _live_server(bus) as base:
        with httpx.stream("GET", base + "/api/events/stream",
                          timeout=8.0) as r:
            # Spawn the publisher early — we don't care if it lands
            # in the same chunk as `: connected` or a later one. The
            # iterator below is single-shot, so we only consume it once.
            published = threading.Event()

            def publisher():
                # Tiny grace so the stream subscription is wired up
                # before publish; the bus is thread-safe either way.
                time.sleep(0.15)
                _emit(bus, severity=Severity.HIGH, source="sse-test",
                      data={"rule_name": "ssehit", "case_id": "sseA"})
                published.set()
            threading.Thread(target=publisher, daemon=True).start()

            saw_connected = False
            saw_data = False
            saw_ssehit = False
            body = b""
            deadline = time.time() + 6.0
            for chunk in r.iter_bytes():
                body += chunk
                if not saw_connected and b": connected" in body:
                    saw_connected = True
                if not saw_data and b"data:" in body:
                    saw_data = True
                if b"ssehit" in body:
                    saw_ssehit = True
                    break
                if time.time() > deadline:
                    break

            check(saw_connected, "saw the initial `: connected` frame")
            check(saw_data, "received a `data:` frame after publish")
            check(saw_ssehit,
                  "published event content reached the SSE stream")


def test_sse_unsubscribes_on_disconnect():
    section("10. SSE handler unsubscribes from the bus on disconnect")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_sse_unsub_"))
    bus = _make_bus(tmp)

    def n_star_subs() -> int:
        return len(bus._subscribers.get("*", []))

    base_count = n_star_subs()

    with _live_server(bus) as base:
        sse_resp = httpx.stream("GET", base + "/api/events/stream",
                                timeout=5.0)
        r = sse_resp.__enter__()
        try:
            deadline = time.time() + 3.0
            seen = b""
            for chunk in r.iter_bytes():
                seen += chunk
                if b": connected" in seen:
                    break
                if time.time() > deadline:
                    break
            during = n_star_subs()
            check(during > base_count,
                  f"subscriber count rose during stream "
                  f"(base={base_count} during={during})")
        finally:
            sse_resp.__exit__(None, None, None)
        # Connection closed; the server's gen() finally block runs
        # and unsubscribes. Give it a short window to settle.
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if n_star_subs() == base_count:
                break
            time.sleep(0.05)
        after = n_star_subs()
        check(after == base_count,
              f"subscriber count returned to base "
              f"(base={base_count} after={after})")


# ── Live page ───────────────────────────────────────────────────────

def test_live_page_uses_eventsource():
    section("11. Live page references EventSource + /api/events/stream")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_dash_live_"))
    bus = _make_bus(tmp)
    client = TestClient(_make_app(bus))
    r = client.get("/")
    check(r.status_code == 200, f"HTTP 200 (got {r.status_code})")
    check("EventSource" in r.text,
          "live page bootstraps an EventSource")
    check("/api/events/stream" in r.text,
          "live page references the SSE endpoint URL")
    check("hx-get=\"/api/events?limit=120\" hx-trigger=\"load, every" not in r.text,
          "old HTMX 1-second polling block is gone")


def main():
    print("=" * 60)
    print("AEGIS — Dashboard Cases View + SSE Test")
    print("=" * 60)

    test_list_cases_basic()
    test_list_cases_nested_case_id()
    test_list_cases_window()
    test_query_case_events_ordering()
    test_cases_page_renders()
    test_case_detail_renders()
    test_case_detail_unknown()
    test_sse_content_type_and_initial_frames()
    test_sse_pushes_published_event()
    test_sse_unsubscribes_on_disconnect()
    test_live_page_uses_eventsource()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
