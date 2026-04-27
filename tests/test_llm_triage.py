"""
AEGIS — LLM Triage Test
========================
Validates the local LLM alert-triage module (R&D backlog #1) using a
deterministic stub backend. The real `llama-cpp-python` backend isn't
exercised here — that's what the standalone benchmark harness is for
(`scripts/bench_llm_triage.py`).

Invariants:
  1. `build_prompt` redacts: full env vars, file contents, cmdline
     beyond 256 chars never reach the user prompt.
  2. `parse_triage_output` accepts a clean JSON object on one line.
  3. `parse_triage_output` accepts a JSON object wrapped in
     ```json ... ``` markdown fencing (small models do this often).
  4. `parse_triage_output` rejects an object whose `confidence` is
     not in the documented enum.
  5. `parse_triage_output` returns None on completely unparseable
     output (real failure mode for under-trained models).
  6. `LlmTriage.triage_event` produces a TriageResult that round-
     trips through to_dict + has model_used / latency / token counts
     populated.
  7. `LlmTriage` start/stop with `enabled=False` is a clean no-op.
  8. `LlmTriage` publishes a `detection.behavioral` enrichment event
     with `source="llm_triage"` and `advisory=True` after handling
     a `response.alert`.
  9. `_MODEL_REGISTRY` has a `default` entry (the ship-default
     pick referenced by the SWOT analysis).
 10. Every registry entry has the required fields: gguf_filename,
     hf_repo, approx_disk_gb, approx_runtime_ram_gb, params_b.
 11. `model_info(unknown)` returns None.
 12. Backend-init failure (missing GGUF) sets `enabled=False` and
     logs, never raises out of `start()`.
"""
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.detection.llm_triage import (
    LlmTriage,
    StaticBackend,
    TriageResult,
    build_prompt,
    parse_triage_output,
    model_info,
    default_model,
    _MODEL_REGISTRY,
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


def _alert_event(**kw) -> Event:
    return Event(
        category=EventCategory.RESPONSE_ALERT,
        severity=Severity.HIGH,
        source="response",
        data=kw.get("data") or {
            "rule_name": "evil_dropper",
            "rule_id": "evil_dropper",
            "filepath": r"C:\Users\alice\Downloads\dropper.exe",
            "pid": 4242,
            "name": "dropper.exe",
            "cmdline": "dropper.exe --c2 https://evil.example.com/beacon",
            "case": {"case_id": "ALERT-1"},
            "mitre_attack": "T1059",
        },
        timestamp=time.time(),
        mitre_attack="T1059",
    )


# ── Prompt redaction ────────────────────────────────────────────────

def test_prompt_redaction():
    section("1. build_prompt redacts long cmdlines + omits raw env vars")
    long_cmd = "evil.exe " + ("X" * 2048)
    ev = _alert_event(data={
        "rule_name": "long_cmd_test",
        "cmdline": long_cmd,
        "env": {"AWS_SECRET_ACCESS_KEY": "should-not-be-here"},
        "case": {"case_id": "REDACT-1"},
    })
    sys_p, user_p = build_prompt(ev)
    check(len(sys_p) > 0, "system prompt non-empty")
    check("evil.exe" in user_p, "process name preserved")
    check(("X" * 2048) not in user_p,
          "cmdline truncated below 2048 char tail")
    check("AWS_SECRET_ACCESS_KEY" not in user_p,
          "raw env vars NOT in prompt")
    check("AEGIS detection event" in user_p,
          "user prompt has the documented header")


# ── Output parsing ──────────────────────────────────────────────────

def test_parse_clean_json():
    section("2. parse_triage_output accepts a clean JSON object")
    raw = json.dumps({
        "confidence": "suspicious",
        "summary": "Outbound C2 to evil.example.com.",
        "next_steps": ["Block destination", "Quarantine binary"],
    })
    r = parse_triage_output(raw)
    check(r is not None, "result returned")
    if r:
        check(r.confidence == "suspicious", "confidence parsed")
        check(len(r.next_steps) == 2, "next_steps count == 2")
        check("evil.example.com" in r.summary, "summary preserved")


def test_parse_markdown_fenced_json():
    section("3. parse_triage_output strips ```json fencing")
    raw = (
        "Here's the JSON:\n```json\n"
        + json.dumps({
            "confidence": "very-likely-malicious",
            "summary": "Reflective DLL injection pattern.",
            "next_steps": ["Kill PID", "Run forensic snapshot"],
        })
        + "\n```\nThanks."
    )
    r = parse_triage_output(raw)
    check(r is not None, "result returned despite fencing + preamble")
    if r:
        check(r.confidence == "very-likely-malicious",
              f"confidence parsed (got {r.confidence})")


def test_parse_brace_elision_fallback():
    section("3b. parse_triage_output recovers when model elides outer braces")
    # Real failure mode observed with Llama-3.2-3B during the
    # 2026-04-25 benchmark — emits JSON-shaped fields without the
    # `{...}` wrapper. Parser must wrap and recover.
    raw = (
        '"confidence": "suspicious", '
        '"summary": "Outlier process tree", '
        '"next_steps": ["Investigate parent", "Snapshot memory"]'
    )
    r = parse_triage_output(raw)
    check(r is not None, "brace-elided output recovered")
    if r:
        check(r.confidence == "suspicious",
              f"confidence (got {r.confidence})")
        check(len(r.next_steps) == 2, "next_steps preserved")


def test_parse_rejects_invalid_confidence():
    section("4. parse_triage_output rejects bogus confidence labels")
    raw = json.dumps({"confidence": "epic", "summary": "x"})
    r = parse_triage_output(raw)
    check(r is None,
          f"invalid confidence → None (got {r and r.confidence})")


def test_parse_handles_garbage():
    section("5. parse_triage_output returns None on garbage")
    for bad in ("", "not even json", "<<garbled>>", "[]"):
        check(parse_triage_output(bad) is None,
              f"garbage rejected: {bad!r}")


# ── Engine round-trip with stub backend ─────────────────────────────

def test_triage_event_round_trip():
    section("6. triage_event populates TriageResult fields")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_llm_rt_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    backend = StaticBackend(json.dumps({
        "confidence": "suspicious",
        "summary": "Stub said this is suspicious.",
        "next_steps": ["Investigate process tree"],
    }))
    backend.name = "test-stub"
    triage = LlmTriage(bus, {
        "enabled": True,
        "backend": backend,
    })
    triage.start()
    try:
        result = triage.triage_event(_alert_event())
    finally:
        triage.stop()

    check(isinstance(result, TriageResult),
          f"got TriageResult (got {type(result).__name__})")
    if isinstance(result, TriageResult):
        check(result.confidence == "suspicious",
              f"confidence (got {result.confidence})")
        check(result.model_used == "test-stub",
              f"model_used set (got {result.model_used})")
        check(result.tokens_in > 0, "tokens_in > 0")
        check(result.tokens_out > 0, "tokens_out > 0")
        d = result.to_dict()
        check(set(d.keys()) >= {"confidence", "summary", "next_steps",
                                "model_used", "latency_ms", "tokens_in",
                                "tokens_out"},
              f"to_dict has documented keys (got {sorted(d.keys())})")


# ── Engine wiring ───────────────────────────────────────────────────

def test_disabled_engine_is_noop():
    section("7. LlmTriage with enabled=false is a clean no-op")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_llm_off_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    triage = LlmTriage(bus, {"enabled": False})
    triage.start()
    triage.stop()
    check(True, "start/stop with disabled config did not raise")


def test_publishes_enrichment_event():
    section("8. LlmTriage publishes detection.behavioral enrichment event")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_llm_pub_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    backend = StaticBackend(json.dumps({
        "confidence": "very-likely-malicious",
        "summary": "Strong evidence of C2 beaconing.",
        "next_steps": ["Block egress", "Snapshot memory"],
    }))
    backend.name = "test-stub-2"
    triage = LlmTriage(bus, {
        "enabled": True,
        "backend": backend,
    })
    captured: list[Event] = []
    bus.subscribe("detection.behavioral", lambda e: captured.append(e))

    triage.start()
    try:
        triage.triage_event(_alert_event())
    finally:
        triage.stop()

    matches = [e for e in captured if e.source == "llm_triage"]
    check(len(matches) == 1,
          f"exactly one llm_triage enrichment event "
          f"(got {len(matches)})")
    if matches:
        ev = matches[0]
        check(ev.severity == Severity.HIGH,
              f"very-likely-malicious → severity HIGH "
              f"(got {ev.severity})")
        check(ev.data.get("advisory") is True,
              "data.advisory == True (never feeds destructive actions)")
        check(ev.data.get("rule_id") == "LLM-TRIAGE",
              "rule_id == LLM-TRIAGE")
        triage_payload = ev.data.get("triage") or {}
        check(triage_payload.get("confidence") == "very-likely-malicious",
              "embedded triage carries the confidence label")


# ── Model registry ──────────────────────────────────────────────────

def test_registry_has_default():
    section("9. Model registry has a default ship pick")
    name = default_model()
    check(name in _MODEL_REGISTRY, f"default '{name}' present in registry")
    check(_MODEL_REGISTRY[name].get("default") is True,
          "registry entry flagged default=True")


def test_registry_entries_complete():
    section("10. Every registry entry has the required fields")
    required = {"gguf_filename", "hf_repo", "approx_disk_gb",
                "approx_runtime_ram_gb", "params_b"}
    for name, info in _MODEL_REGISTRY.items():
        missing = required - set(info)
        check(not missing,
              f"{name} has all required fields",
              f"missing: {missing}")
        check(info["gguf_filename"].endswith(".gguf"),
              f"{name} GGUF filename ends with .gguf")


def test_unknown_model_returns_none():
    section("11. model_info(unknown) returns None")
    check(model_info("definitely-not-a-real-model-2099") is None,
          "unknown model name returns None")


# ── Backend init failure path ───────────────────────────────────────

def test_missing_gguf_disables_cleanly():
    section("12. Missing GGUF disables the engine without raising")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_llm_missing_"))
    bus = EventBus(db_path=str(tmp / "events.db"))
    triage = LlmTriage(bus, {
        "enabled": True,
        "model": default_model(),
        "models_dir": str(tmp / "no-such-dir"),
    })
    raised = False
    try:
        triage.start()
    except Exception as e:
        raised = True
        check(False, "start() must not raise on missing GGUF",
              repr(e))
    if not raised:
        check(triage.enabled is False,
              "start() flipped enabled=False instead of crashing")
        triage.stop()


def main():
    print("=" * 60)
    print("AEGIS — LLM Triage Test")
    print("=" * 60)

    test_prompt_redaction()
    test_parse_clean_json()
    test_parse_markdown_fenced_json()
    test_parse_brace_elision_fallback()
    test_parse_rejects_invalid_confidence()
    test_parse_handles_garbage()
    test_triage_event_round_trip()
    test_disabled_engine_is_noop()
    test_publishes_enrichment_event()
    test_registry_has_default()
    test_registry_entries_complete()
    test_unknown_model_returns_none()
    test_missing_gguf_disables_cleanly()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
