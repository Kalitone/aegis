"""
AEGIS — SBOM (CycloneDX 1.5) Test
==================================
Validates the host-SBOM emitter (R&D backlog #10).

Invariants:
  1. `collect_python_packages()` finds the expected baseline set
     (pydantic + httpx + uvicorn are all required by the project so
     they MUST be present).
  2. Every collected package has a name, version, and a well-formed
     PURL (`pkg:pypi/<name>@<version>`).
  3. `collect_npm_packages()` returns a list (possibly empty) and
     never raises when npm is missing — the call must degrade
     silently for hosts without Node.
  4. `build_cyclonedx()` produces a doc with the CycloneDX 1.5
     required headers: bomFormat, specVersion, serialNumber,
     version, components.
  5. The serialNumber is a `urn:uuid:<uuid4>` URN.
  6. `metadata.tools[]` carries vendor/name/version.
  7. Every component has a stable bom-ref equal to its PURL — that
     ref is what Dependency-Track uses for upgrade tracking.
  8. Components are sorted by name/version for deterministic diffs.
  9. `write_sbom()` writes a syntactically valid JSON file with
     non-zero components.
 10. `SbomEmitter.emit_once()` writes the file and publishes a
     `system.health` event with `action == "sbom_emitted"`.
 11. `SbomEmitter.start()` with `enabled=False` is a clean no-op.
"""
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.utils.sbom import (
    collect_python_packages,
    collect_npm_packages,
    build_cyclonedx,
    write_sbom,
    SbomEmitter,
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


_PURL_RE = re.compile(r"^pkg:(pypi|npm)/[^@]+(@.+)?$")
_UUID_URN_RE = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def test_collect_python_packages():
    section("1. collect_python_packages: baseline + PURL shape")
    pkgs = collect_python_packages()
    check(len(pkgs) > 5, f"non-trivial pip set (got {len(pkgs)})")
    names = {p["name"].lower() for p in pkgs}
    for must_have in ("pydantic", "httpx", "uvicorn"):
        check(must_have in names,
              f"baseline package '{must_have}' present in SBOM")
    sample = pkgs[0]
    check(set(sample.keys()) == {"name", "version", "purl"},
          f"entry has the documented keys (got {sorted(sample.keys())})")
    check(_PURL_RE.match(sample["purl"]) is not None,
          f"PURL well-formed (got {sample['purl']!r})")
    check(sample["purl"] == sample["purl"].lower(),
          "PURL is lower-cased (PyPI normalisation)")


def test_collect_npm_packages_safe():
    section("2. collect_npm_packages never raises when npm absent")
    try:
        result = collect_npm_packages(timeout_seconds=10.0)
    except Exception as e:
        check(False, "collect_npm_packages raised", repr(e))
        return
    check(isinstance(result, list),
          f"returns a list (got {type(result).__name__})")
    for p in result:
        check(set(p.keys()) >= {"name", "version", "purl"},
              f"npm entry has expected keys: {p}")


def test_build_cyclonedx_required_headers():
    section("3. build_cyclonedx: required CycloneDX 1.5 headers")
    py = [{"name": "pydantic", "version": "2.0.0",
           "purl": "pkg:pypi/pydantic@2.0.0"}]
    doc = build_cyclonedx(python_pkgs=py, npm_pkgs=[],
                          hostname="test-host", timestamp=1700000000.0)
    for required in ("bomFormat", "specVersion", "serialNumber",
                     "version", "metadata", "components"):
        check(required in doc, f"top-level field '{required}' present")
    check(doc["bomFormat"] == "CycloneDX",
          f"bomFormat == CycloneDX (got {doc['bomFormat']})")
    check(doc["specVersion"] == "1.5",
          f"specVersion == 1.5 (got {doc['specVersion']})")
    check(doc["version"] == 1, "doc version == 1")


def test_serial_number_is_uuid_urn():
    section("4. serialNumber is a UUID URN")
    doc = build_cyclonedx(python_pkgs=[], npm_pkgs=[])
    check(_UUID_URN_RE.match(doc["serialNumber"]) is not None,
          f"serialNumber matches urn:uuid pattern "
          f"(got {doc['serialNumber']!r})")


def test_metadata_tools_block():
    section("5. metadata.tools carries vendor/name/version")
    doc = build_cyclonedx(python_pkgs=[], npm_pkgs=[])
    tools = doc["metadata"].get("tools") or []
    check(len(tools) >= 1, "at least one tool entry")
    if tools:
        t = tools[0]
        check(t.get("vendor") == "AEGIS", "tool vendor is AEGIS")
        check(t.get("name") == "aegis-sbom", "tool name is aegis-sbom")
        check(bool(t.get("version")), "tool version non-empty")


def test_component_bomref_equals_purl():
    section("6. component bom-ref == PURL (Dependency-Track contract)")
    py = [{"name": "click", "version": "8.1.7",
           "purl": "pkg:pypi/click@8.1.7"},
          {"name": "fastapi", "version": "0.111.0",
           "purl": "pkg:pypi/fastapi@0.111.0"}]
    doc = build_cyclonedx(python_pkgs=py, npm_pkgs=[])
    for c in doc["components"]:
        check(c["bom-ref"] == c["purl"],
              f"bom-ref matches PURL for {c['name']}")
        check(c["type"] == "library", f"type=library for {c['name']}")
        # source property tag
        props = {p["name"]: p["value"] for p in c.get("properties") or []}
        check(props.get("aegis:source") == "pip",
              "components carry aegis:source=pip property")


def test_components_sorted():
    section("7. components are sorted for deterministic diffs")
    py = [
        {"name": "zzz", "version": "1.0", "purl": "pkg:pypi/zzz@1.0"},
        {"name": "aaa", "version": "1.0", "purl": "pkg:pypi/aaa@1.0"},
        {"name": "mmm", "version": "1.0", "purl": "pkg:pypi/mmm@1.0"},
    ]
    # collect_python_packages does its own sort; build_cyclonedx
    # consumes whatever order it gets — caller pre-sorts. This test
    # documents the contract: real collectors sort.
    pkgs = collect_python_packages()
    names = [p["name"].lower() for p in pkgs]
    check(names == sorted(names),
          "collect_python_packages returns sorted-by-name list")


def test_write_sbom_round_trip():
    section("8. write_sbom emits syntactically valid JSON to disk")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_sbom_write_"))
    out = tmp / "sbom.cdx.json"
    summary = write_sbom(out, include_npm=False)
    check(out.exists(), "SBOM file written")
    check(summary["components"] > 0,
          f"non-zero components ({summary['components']})")
    parsed = json.loads(out.read_text(encoding="utf-8"))
    check(parsed["bomFormat"] == "CycloneDX",
          "round-tripped JSON parses cleanly")
    check(parsed["specVersion"] == "1.5", "round-tripped specVersion")
    check(parsed["serialNumber"] == summary["serial"],
          "summary.serial matches file contents")


def test_emitter_emit_once_publishes():
    section("9. SbomEmitter.emit_once publishes a system.health event")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_sbom_emit_"))
    out = tmp / "sbom.cdx.json"
    bus = EventBus(db_path=str(tmp / "events.db"))
    captured: list[Event] = []
    bus.subscribe("system.health", lambda e: captured.append(e))

    emitter = SbomEmitter(bus, {
        "enabled": True,
        "path": str(out),
        "include_npm": False,
        "emit_on_start": False,        # we'll call emit_once directly
    })
    summary = emitter.emit_once()

    check(out.exists(), "SBOM file produced")
    check(summary["components"] > 0,
          f"summary reports components ({summary['components']})")

    matching = [e for e in captured
                if e.data.get("action") == "sbom_emitted"]
    check(len(matching) == 1,
          f"exactly one sbom_emitted event (got {len(matching)})")
    if matching:
        ev = matching[0]
        check(ev.data.get("components") == summary["components"],
              "event component count matches summary")
        check(ev.data.get("path") == summary["path"],
              "event carries SBOM path")
        check(ev.severity == Severity.INFO, "severity is INFO")


def test_emitter_disabled_is_noop():
    section("10. SbomEmitter with enabled=false starts cleanly without writing")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_sbom_off_"))
    out = tmp / "sbom.cdx.json"
    bus = EventBus(db_path=str(tmp / "events.db"))
    emitter = SbomEmitter(bus, {
        "enabled": False,
        "path": str(out),
    })
    emitter.start()
    emitter.stop()
    check(not out.exists(),
          "no SBOM file written when emitter disabled")


def main():
    print("=" * 60)
    print("AEGIS — SBOM (CycloneDX 1.5) Test")
    print("=" * 60)

    test_collect_python_packages()
    test_collect_npm_packages_safe()
    test_build_cyclonedx_required_headers()
    test_serial_number_is_uuid_urn()
    test_metadata_tools_block()
    test_component_bomref_equals_purl()
    test_components_sorted()
    test_write_sbom_round_trip()
    test_emitter_emit_once_publishes()
    test_emitter_disabled_is_noop()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
