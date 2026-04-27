"""
AEGIS — Process Mitigation Policies Test
=========================================
Validates the SetProcessMitigationPolicy bundle applied at bootstrap.
The bundle is irrevocable per-process, so we don't try to apply real
policies inside the test runner — that would silently affect every
later test in the same Python invocation. Instead we monkey-patch the
ctypes call so we exercise the dispatch / report logic against a
controlled fake.

Invariants:
  1. Non-Windows: every policy is reported as "skipped: not on
     Windows" with no system call attempted.
  2. Safe bundle has the documented set of labels.
  3. Aggressive=False omits the dynamic-code / child-process labels.
  4. Aggressive=True adds them.
  5. A successful Win32 call (BOOL=1) lands the label in `applied`.
  6. A failing Win32 call (BOOL=0, GetLastError=5) lands the label
     in `failed` with the winerror code.
  7. A raised exception inside the dispatcher routes to `failed`
     with `winerror=-1` and an `error` string — never propagates.
  8. Each policy uses the documented PROCESS_MITIGATION_POLICY id;
     the safe bundle covers exactly the four documented entries.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.utils import process_mitigation as pm


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


def _safe_labels() -> set[str]:
    return {label for _, _, label in pm._safe_bundle()}


def _aggressive_labels() -> set[str]:
    return {label for _, _, label in pm._aggressive_bundle()}


def test_safe_bundle_shape():
    section("1. Safe bundle has the documented label set")
    expected = {
        "extension_point_disable",
        "strict_handle_check",
        "image_load_restrictions",
        "non_system_font_disable",
    }
    check(_safe_labels() == expected,
          f"safe bundle labels match (got {_safe_labels()})")
    check(len(pm._safe_bundle()) == 4,
          "exactly four entries in safe bundle")


def test_aggressive_bundle_shape():
    section("2. Aggressive bundle has the documented label set")
    expected = {"prohibit_dynamic_code", "no_child_process"}
    check(_aggressive_labels() == expected,
          f"aggressive labels match (got {_aggressive_labels()})")


def test_safe_and_aggressive_disjoint():
    section("3. Safe + aggressive label sets are disjoint")
    check(not (_safe_labels() & _aggressive_labels()),
          "no overlap between safe and aggressive bundles")


def test_policy_ids_unique():
    section("4. Policy IDs are unique across both bundles")
    ids = [pid for pid, _, _ in pm._safe_bundle() + pm._aggressive_bundle()]
    check(len(ids) == len(set(ids)),
          f"policy IDs unique (got {ids})")


def test_non_windows_skips_everything(monkeypatch):
    section("5. Non-Windows path skips every policy without calling Win32")

    monkeypatch.setattr(pm, "_is_windows", lambda: False)
    called = {"count": 0}

    def trap(*_a, **_kw):
        called["count"] += 1
        raise AssertionError("_set_one must not run on non-Windows")

    monkeypatch.setattr(pm, "_set_one", trap)

    report = pm.apply_mitigations(aggressive=True)
    expected = _safe_labels() | _aggressive_labels()
    skipped = {entry["label"] for entry in report["skipped"]}
    check(skipped == expected, "every label skipped on non-Windows",
          f"got {skipped}")
    check(report["applied"] == [], "applied list is empty")
    check(report["failed"] == [], "failed list is empty")
    check(called["count"] == 0,
          f"_set_one never called (got {called['count']})")


def test_apply_success(monkeypatch):
    section("6. All-success path: every label lands in 'applied'")

    monkeypatch.setattr(pm, "_is_windows", lambda: True)
    monkeypatch.setattr(pm, "_set_one", lambda *_a, **_kw: None)

    report = pm.apply_mitigations(aggressive=False)
    check(set(report["applied"]) == _safe_labels(),
          "all safe labels applied")
    check(report["failed"] == [], "no failures")
    check(report["skipped"] == [], "no skips on Windows")
    check(report["aggressive"] is False, "aggressive flag preserved")


def test_apply_aggressive_adds_extras(monkeypatch):
    section("7. Aggressive=True adds the dynamic-code + child-process pair")

    monkeypatch.setattr(pm, "_is_windows", lambda: True)
    monkeypatch.setattr(pm, "_set_one", lambda *_a, **_kw: None)

    report = pm.apply_mitigations(aggressive=True)
    check(set(report["applied"]) == _safe_labels() | _aggressive_labels(),
          "applied set covers safe + aggressive labels")
    check(report["aggressive"] is True, "aggressive flag preserved")


def test_apply_partial_failure(monkeypatch):
    section("8. Win32 failure routes to 'failed' with winerror code")

    monkeypatch.setattr(pm, "_is_windows", lambda: True)

    def fake_set(policy_id, _value):
        # Fail every call with ERROR_ACCESS_DENIED (5).
        return 5

    monkeypatch.setattr(pm, "_set_one", fake_set)

    report = pm.apply_mitigations(aggressive=False)
    check(report["applied"] == [], "no successful applies")
    failed_labels = {f["label"] for f in report["failed"]}
    check(failed_labels == _safe_labels(),
          "every safe label captured in failed[]")
    winerrs = {f["winerror"] for f in report["failed"]}
    check(winerrs == {5}, f"winerror == 5 for every failure (got {winerrs})")


def test_apply_handles_exception(monkeypatch):
    section("9. Exception inside _set_one is captured, never propagated")

    monkeypatch.setattr(pm, "_is_windows", lambda: True)

    def boom(*_a, **_kw):
        raise OSError("simulated kernel32 unavailable")

    monkeypatch.setattr(pm, "_set_one", boom)

    try:
        report = pm.apply_mitigations(aggressive=False)
    except Exception as e:
        check(False, "apply_mitigations raised", f"{e!r}")
        return

    check(report["applied"] == [], "no applies on raise")
    check(len(report["failed"]) == len(pm._safe_bundle()),
          "every label landed in failed[]")
    for entry in report["failed"]:
        check(entry["winerror"] == -1,
              f"{entry['label']} winerror == -1 sentinel")
        check("simulated kernel32" in entry.get("error", ""),
              f"{entry['label']} carries the exception text")


def test_mixed_success_and_failure(monkeypatch):
    section("10. Mixed outcome: success + winerror routed correctly")

    monkeypatch.setattr(pm, "_is_windows", lambda: True)

    failing_id = pm._POLICY_FONT_DISABLE

    def fake_set(policy_id, _value):
        return 87 if policy_id == failing_id else None  # ERROR_INVALID_PARAMETER

    monkeypatch.setattr(pm, "_set_one", fake_set)

    report = pm.apply_mitigations(aggressive=False)
    check("non_system_font_disable" not in report["applied"],
          "failing policy excluded from applied[]")
    check(any(f["label"] == "non_system_font_disable" and f["winerror"] == 87
              for f in report["failed"]),
          "failing policy captured with the right winerror")
    check(set(report["applied"]) == _safe_labels() - {"non_system_font_disable"},
          "every other safe label still in applied[]")


# ── Tiny monkeypatch helper so we don't need pytest ──────────────────

class _Monkey:
    def __init__(self):
        self._undo: list = []

    def setattr(self, target, name, value):
        old = getattr(target, name)
        self._undo.append((target, name, old))
        setattr(target, name, value)

    def undo(self):
        while self._undo:
            target, name, old = self._undo.pop()
            setattr(target, name, old)


def _run(test_fn):
    mp = _Monkey()
    try:
        if test_fn.__code__.co_argcount == 1:
            test_fn(mp)
        else:
            test_fn()
    finally:
        mp.undo()


def main():
    print("=" * 60)
    print("AEGIS — Process Mitigation Policies Test")
    print("=" * 60)

    _run(test_safe_bundle_shape)
    _run(test_aggressive_bundle_shape)
    _run(test_safe_and_aggressive_disjoint)
    _run(test_policy_ids_unique)
    _run(test_non_windows_skips_everything)
    _run(test_apply_success)
    _run(test_apply_aggressive_adds_extras)
    _run(test_apply_partial_failure)
    _run(test_apply_handles_exception)
    _run(test_mixed_success_and_failure)

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
