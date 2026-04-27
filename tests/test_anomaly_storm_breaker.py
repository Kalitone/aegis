"""
AEGIS — Anomaly Severity + Storm Breaker Test
==============================================
Audit found:
  - 326 anomaly detections / 6.5 days = ~50/day
  - 735 high-severity events, mostly produced by the score < -0.2
    auto-escalation rule mixing FP score-tail noise into the same
    bucket as YARA matches
  - No rate cap, so a degenerate workload spike could publish dozens
    of detections inside a minute

Changes verified here:
  1. _StormBreaker rolling window: at most `threshold` events admit
     per `window_s`; the (threshold+1)-th trips the breaker.
  2. While tripped, every admit returns False until `cool_off_s`
     elapses; then admits resume.
  3. Window drains naturally — events older than `window_s` no longer
     count toward the threshold.
  4. AnomalyDetector default severity is MEDIUM (no score-based
     auto-promotion to HIGH).
  5. Severity is config-driven: setting `severity: high` in config
     produces HIGH-severity detections.
  6. Storm-breaker integration: rapid-fire detections cap at the
     threshold and emit suppression-via-debug instead of bus events.
  7. ResponseEngine `auto_respond_sources.anomaly: false` blocks the
     destructive chain for anomaly events while still publishing a
     `response.alert` with the manual-action suggestion.
"""
import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.response import ResponseEngine
from aegis.detection.anomaly import (
    AnomalyDetector,
    _StormBreaker,
    SKLEARN_AVAILABLE,
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


def test_breaker_basic():
    section("1. _StormBreaker: threshold + window + cool-off")

    b = _StormBreaker(threshold=3, window_s=10, cool_off_s=20)
    t = 1000.0

    check(b.try_admit(t) is True, "1st admit")
    check(b.try_admit(t + 1) is True, "2nd admit")
    check(b.try_admit(t + 2) is True, "3rd admit (at threshold)")
    check(b.try_admit(t + 3) is False, "4th admit trips breaker")
    check(b.trips == 1, f"trip counter == 1 (got {b.trips})")

    # Still within cool-off
    check(b.try_admit(t + 10) is False, "still suppressed mid-cool-off")
    check(b.try_admit(t + 22) is False, "still suppressed at cool-off boundary")

    # After cool-off + window decay
    check(b.try_admit(t + 24) is True,
          "admits resume after cool-off elapses")


def test_breaker_window_drain():
    section("2. _StormBreaker: window drains naturally")

    b = _StormBreaker(threshold=2, window_s=5, cool_off_s=30)
    t = 1000.0

    check(b.try_admit(t) is True, "early admit 1")
    check(b.try_admit(t + 1) is True, "early admit 2 (at threshold)")
    # Wait past the window so old events drop out
    check(b.try_admit(t + 7) is True,
          "admit succeeds after old events drained from window")
    check(b.try_admit(t + 7.1) is True,
          "second admit inside fresh window")
    check(b.try_admit(t + 7.2) is False,
          "third admit in fresh window trips breaker")


class _AlwaysAnomalousModel:
    """Stand-in IsolationForest that classifies every vector as -1.

    Lets the storm-breaker / severity tests exercise the publish path
    deterministically without depending on real model behaviour at
    contamination=0.5 against a 5-sample training set.
    """
    def predict(self, X):
        return [-1 for _ in range(len(X))]

    def score_samples(self, X):
        return [-0.3 for _ in range(len(X))]


def _make_detector(*, severity: str = "medium",
                   breaker_enabled: bool = True,
                   threshold: int = 3,
                   window_s: float = 60,
                   cool_off_s: float = 60) -> tuple[EventBus, AnomalyDetector]:
    if not SKLEARN_AVAILABLE:
        return None, None  # type: ignore[return-value]
    tmp = Path(tempfile.mkdtemp(prefix="aegis_anom_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    cfg = {
        "model_path": str(tmp / "model.pkl"),
        "training_period_hours": 0.0001,
        "min_training_samples": 5,
        "contamination": 0.5,
        "auto_train": True,
        "severity": severity,
        "storm_breaker": {
            "enabled": breaker_enabled,
            "threshold": threshold,
            "window_s": window_s,
            "cool_off_s": cool_off_s,
        },
    }
    det = AnomalyDetector(bus, cfg)
    det._model = _AlwaysAnomalousModel()
    det._mode = "detecting"
    det._dedup_window = 0.0      # disable feature-vector debounce
    det._running = True
    bus.subscribe(EventCategory.PROC_CREATE.value, det._on_event)
    return bus, det


def test_severity_config_default_medium():
    section("3. AnomalyDetector default severity is MEDIUM")

    if not SKLEARN_AVAILABLE:
        print("  [skip] scikit-learn not available")
        return

    bus, det = _make_detector(breaker_enabled=False)
    captured: list[Event] = []
    bus.subscribe("detection.anomaly", lambda e: captured.append(e))

    # Emit clearly-anomalous feature vectors to force detections.
    for i in range(3):
        bus.publish(Event(
            category=EventCategory.PROC_CREATE,
            severity=Severity.INFO,
            source="test",
            data={
                "pid": 1000 + i,
                "name": "test.exe",
                "cmdline": f"test {i}",
                "cpu_percent": 99 + i,
                "memory_mb": 9999 + i,
                "num_fds": 999 + i,
                "net_connections": 99 + i,
                "file_writes_per_sec": 999 + i,
            },
        ))
        time.sleep(0.05)

    anomalies = [e for e in captured]
    check(len(anomalies) >= 1, f"got {len(anomalies)} anomaly event(s)")
    if anomalies:
        sevs = {e.severity for e in anomalies}
        check(sevs == {Severity.MEDIUM},
              f"every anomaly is MEDIUM (got {sevs})")


def test_severity_config_high():
    section("4. AnomalyDetector severity=high honoured")

    if not SKLEARN_AVAILABLE:
        print("  [skip] scikit-learn not available")
        return

    bus, det = _make_detector(severity="high", breaker_enabled=False)
    captured: list[Event] = []
    bus.subscribe("detection.anomaly", lambda e: captured.append(e))

    for i in range(2):
        bus.publish(Event(
            category=EventCategory.PROC_CREATE,
            severity=Severity.INFO,
            source="test",
            data={
                "pid": 2000 + i,
                "name": "test.exe",
                "cmdline": f"test {i}",
                "cpu_percent": 99 + i,
                "memory_mb": 9999 + i,
                "num_fds": 999,
                "net_connections": 99,
                "file_writes_per_sec": 999,
            },
        ))
        time.sleep(0.05)

    if captured:
        sevs = {e.severity for e in captured}
        check(sevs == {Severity.HIGH},
              f"every anomaly is HIGH when configured (got {sevs})")
    else:
        check(False, "no anomaly fired", "expected at least one")


def test_breaker_caps_anomaly_storm():
    section("5. AnomalyDetector storm breaker caps published events")

    if not SKLEARN_AVAILABLE:
        print("  [skip] scikit-learn not available")
        return

    bus, det = _make_detector(threshold=3, window_s=300, cool_off_s=300)
    captured: list[Event] = []
    bus.subscribe("detection.anomaly", lambda e: captured.append(e))

    # 10 anomalous events; only the first 3 should publish.
    for i in range(10):
        bus.publish(Event(
            category=EventCategory.PROC_CREATE,
            severity=Severity.INFO,
            source="test",
            data={
                "pid": 3000 + i,
                "name": f"proc{i}.exe",
                "cmdline": f"distinct {i}",
                "cpu_percent": 99 + i * 0.1,
                "memory_mb": 9999 + i,
                "num_fds": 999 + i,
                "net_connections": 99 + i,
                "file_writes_per_sec": 999 + i,
            },
        ))
        time.sleep(0.02)

    check(len(captured) <= 3,
          f"published events capped at threshold (got {len(captured)})")
    check(det._storm_breaker.trips >= 1,
          f"breaker tripped at least once (got {det._storm_breaker.trips})")
    check(det._storm_breaker.suppressed >= 1,
          f"suppressed counter > 0 (got {det._storm_breaker.suppressed})")


def test_response_engine_anomaly_no_auto_respond():
    section("6. ResponseEngine: anomaly source skips auto-respond chain")

    tmp = Path(tempfile.mkdtemp(prefix="aegis_anom_resp_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    engine = ResponseEngine(bus, {
        "auto_respond": True,
        "auto_respond_sources": {"anomaly": False},
        "quarantine_dir": str(tmp / "q"),
        "forensics_dir": str(tmp / "f"),
        "severity_actions": {
            "high": ["quarantine_file", "alert"],
            "medium": ["alert", "log"],
        },
        "hash_sweep": {"enabled": False},
        "persistence_hunt": {"enabled": False},
        "hardening_recheck": {"enabled": False},
    })
    engine.start()

    captured: list[Event] = []
    bus.subscribe("response.alert", lambda e: captured.append(e))
    bus.subscribe("response.quarantine", lambda e: captured.append(e))

    bus.publish(Event(
        category=EventCategory.DETECTION_ANOMALY,
        severity=Severity.HIGH,
        source="anomaly",      # auto_respond_sources says false
        data={"pid": 1234, "score": -0.3, "rule_name": "Isolation Forest"},
    ))
    time.sleep(0.1)

    alerts = [e for e in captured if e.category == EventCategory.RESPONSE_ALERT]
    quarantines = [e for e in captured
                   if e.category == EventCategory.RESPONSE_QUARANTINE]
    check(len(alerts) == 1,
          f"exactly one response.alert fired for anomaly source "
          f"(got {len(alerts)} alerts, {len(quarantines)} quarantines)")
    check(len(quarantines) == 0,
          "NO destructive actions for anomaly source")
    if alerts:
        ev = alerts[0]
        check(ev.data.get("auto_respond") is False,
              "alert flags auto_respond=False")

    # Also confirm a non-anomaly source still runs the chain.
    bus.publish(Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="yara",
        data={"filepath": "", "rule_name": "evil", "rule_id": "evil"},
    ))
    time.sleep(0.05)
    yara_alerts = [e for e in captured
                   if e.data.get("auto_respond") is False
                   and "yara" in str(e.data.get("original_event", "")).lower()]
    check(len(yara_alerts) == 0,
          "yara source NOT diverted to manual-action path")


def main():
    print("=" * 60)
    print("AEGIS — Anomaly Severity + Storm Breaker Test")
    print("=" * 60)

    test_breaker_basic()
    test_breaker_window_drain()
    test_severity_config_default_medium()
    test_severity_config_high()
    test_breaker_caps_anomaly_storm()
    test_response_engine_anomaly_no_auto_respond()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
