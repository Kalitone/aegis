"""
AEGIS — Config Schema (Pydantic v2) Test
=========================================
Validates the typed-config layer added in #8 of the R&D backlog.

Two halves:

  * `validate_config_dict` — pure function from a merged-config dict
    to a list of {loc, msg, type} records. The contract callers
    depend on: empty list iff the config is clean; dotted field paths
    in `loc` so a user can find the typo without reading source.
  * `AegisConfig` integration — soft-by-default validation logs
    warnings, strict mode raises SystemExit(5). The shipped
    config/aegis.yaml validates clean today (regression catch).

Invariants:
  1. The shipped config validates without errors. (If this breaks,
     either the YAML drifted or the schema needs updating — both
     are bugs we want loud.)
  2. An unknown top-level key produces an error rooted at that key.
  3. An unknown nested key (e.g. `monitors.fim.bogus_field`) errors
     with a `loc` that locates it.
  4. A wrong-type value (port: "not-a-number") errors.
  5. A wrong Literal value (severity: "epic") errors.
  6. Defaults: validating an empty dict succeeds (every section has
     a default-factory).
  7. AegisConfig with `validate_strict=True` raises SystemExit on a
     malformed YAML; with strict=False it sets `validation_errors`
     but constructs successfully.
  8. `validation_errors` is empty after a clean load.
  9. `schema_dict()` returns a JSON-Schema-shaped dict with the
     expected top-level $defs (CoreConfig, MonitorsConfig, …) so
     editor integrations get useful completions.
 10. Severity-action keys are constrained to legal severity names
     (catches `severity_actions: { hgih: [...] }`).
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from aegis.core.config import AegisConfig
from aegis.core.config_schema import (
    validate_config_dict,
    schema_dict,
    AegisSettings,
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


def _shipped_yaml() -> dict:
    p = Path(__file__).resolve().parent.parent / "config" / "aegis.yaml"
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _has_loc(errors: list[dict], loc_substr: str) -> bool:
    return any(loc_substr in e["loc"] for e in errors)


def test_shipped_config_validates_clean():
    section("1. Shipped config/aegis.yaml validates without errors")
    errors = validate_config_dict(_shipped_yaml())
    check(errors == [],
          "no validation errors against shipped YAML",
          f"got: {errors}")


def test_unknown_top_level_key():
    section("2. Unknown top-level key produces an error")
    data = _shipped_yaml()
    data["bogus_section"] = {"x": 1}
    errors = validate_config_dict(data)
    check(any("bogus_section" in e["loc"] for e in errors),
          "bogus_section flagged as extra/forbidden",
          f"errors: {errors}")


def test_unknown_nested_key():
    section("3. Unknown nested key produces an error rooted at the path")
    data = _shipped_yaml()
    data.setdefault("monitors", {}).setdefault("fim", {})["bogus_field"] = 1
    errors = validate_config_dict(data)
    check(_has_loc(errors, "monitors.fim.bogus_field"),
          "loc points to monitors.fim.bogus_field",
          f"errors: {errors}")


def test_wrong_type_value():
    section("4. Wrong-type values fail validation")
    data = _shipped_yaml()
    # port should be int; pass a non-numeric string Pydantic can't coerce.
    data.setdefault("dashboard_web", {})["port"] = "not-a-number"
    errors = validate_config_dict(data)
    check(_has_loc(errors, "dashboard_web.port"),
          "dashboard_web.port flagged",
          f"errors: {errors}")


def test_wrong_literal_value():
    section("5. Wrong Literal values fail validation")
    data = _shipped_yaml()
    data.setdefault("alerting", {}).setdefault("webhook", {})["min_severity"] = "epic"
    errors = validate_config_dict(data)
    check(_has_loc(errors, "alerting.webhook.min_severity"),
          "alerting.webhook.min_severity literal flagged",
          f"errors: {errors}")


def test_empty_dict_validates():
    section("6. Empty dict validates (defaults populate every section)")
    errors = validate_config_dict({})
    check(errors == [],
          "empty config has no validation errors")


def test_aegisconfig_soft_mode():
    section("7. AegisConfig soft mode constructs despite invalid YAML")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_cfg_soft_"))
    bad = tmp / "bad.yaml"
    bad.write_text("monitors:\n  fim:\n    bogus_field: 42\n",
                   encoding="utf-8")
    try:
        cfg = AegisConfig(str(bad), validate_strict=False)
        check(len(cfg.validation_errors) >= 1,
              f"soft mode collected validation errors "
              f"(got {len(cfg.validation_errors)})")
        check(any("bogus_field" in e["loc"]
                  for e in cfg.validation_errors),
              "validation_errors mentions the bad path")
    except SystemExit:
        check(False, "soft mode must not raise SystemExit")


def test_aegisconfig_strict_mode_raises():
    section("8. AegisConfig strict mode raises SystemExit(5) on bad YAML")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_cfg_strict_"))
    bad = tmp / "bad.yaml"
    bad.write_text("dashboard_web:\n  port: not-a-number\n",
                   encoding="utf-8")
    raised = False
    code = None
    try:
        AegisConfig(str(bad), validate_strict=True)
    except SystemExit as e:
        raised = True
        code = e.code
    check(raised, "strict mode raised SystemExit")
    check(code == 5, f"exit code is 5 (got {code})")


def test_aegisconfig_clean_yaml_no_errors():
    section("9. AegisConfig validation_errors empty after clean load")
    shipped = Path(__file__).resolve().parent.parent / "config" / "aegis.yaml"
    cfg = AegisConfig(str(shipped))
    check(cfg.validation_errors == [],
          "shipped config produces zero validation errors at runtime",
          f"errors: {cfg.validation_errors}")


def test_schema_dict_shape():
    section("10. schema_dict() produces a JSON-Schema-shaped result")
    s = schema_dict()
    check(isinstance(s, dict), "result is a dict")
    check("$defs" in s or "definitions" in s,
          "schema declares a defs/definitions block")
    defs = s.get("$defs") or s.get("definitions") or {}
    for name in ("CoreConfig", "MonitorsConfig", "DetectionConfig",
                 "ResponseConfig", "AlertingConfig", "OcsfSinkConfig"):
        check(name in defs, f"$defs contains {name}",
              f"keys: {sorted(defs.keys())[:8]}…")


def test_severity_action_keys_constrained():
    section("11. response.severity_actions keys must be legal severities")
    data = _shipped_yaml()
    data.setdefault("response", {}).setdefault("severity_actions", {})
    data["response"]["severity_actions"]["hgih"] = ["alert"]
    errors = validate_config_dict(data)
    check(any("severity_actions" in e["loc"] for e in errors),
          "typo'd severity key flagged under response.severity_actions",
          f"errors: {errors}")


def test_strict_class_attached_to_top_level():
    section("12. Top-level model also rejects unknown keys")
    # Direct model_validate so we exercise the same path the CLI hits.
    from pydantic import ValidationError
    raised = False
    try:
        AegisSettings.model_validate({"completely_unknown": 1})
    except ValidationError:
        raised = True
    check(raised, "AegisSettings.model_validate rejects unknown top-level key")


def main():
    print("=" * 60)
    print("AEGIS — Config Schema (Pydantic v2) Test")
    print("=" * 60)

    test_shipped_config_validates_clean()
    test_unknown_top_level_key()
    test_unknown_nested_key()
    test_wrong_type_value()
    test_wrong_literal_value()
    test_empty_dict_validates()
    test_aegisconfig_soft_mode()
    test_aegisconfig_strict_mode_raises()
    test_aegisconfig_clean_yaml_no_errors()
    test_schema_dict_shape()
    test_severity_action_keys_constrained()
    test_strict_class_attached_to_top_level()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
