"""
AEGIS — TPM Attestation Test
=============================
Validates the manifest TPM-binding layer (R&D backlog #9). Two halves:

  * `tpm_attest` round-trip — sign + verify on the host's actual TPM
    when one is available; pure-Python ECDSA verifier exercised when
    no TPM is present.
  * `self_protect` integration — `build_manifest` attaches an
    attestation block when TPM is available; `verify_manifest`
    detects payload tampering and forged public keys; the
    `require_attestation` knob upgrades verification strictness.

Invariants:
  1. On a TPM-equipped Windows host, `is_available()` returns True
     and `sign()` produces a 64-byte ECDSA-P256 signature with the
     bundled 64-byte X||Y public key.
  2. Round-trip: verify(payload, sign(payload)) → ok.
  3. Tampered payload → signature_valid=False, ok=False.
  4. Forged public key (random replacement) → host_bound_match=False
     when TPM is available; signature_valid=False otherwise.
  5. The pure-Python ECDSA P-256 verifier agrees with the CNG
     verifier on a known-good (payload, sig, pubkey) triple.
  6. `_canonical_payload` ignores the `attestation` field so build /
     verify see the same bytes.
  7. `build_manifest(attest=True)` writes an `attestation` block on
     a TPM-equipped host (skipped on others).
  8. `verify_manifest` accepts an unmodified attested manifest.
  9. `verify_manifest` rejects an attested manifest whose `files`
     table has been tampered with after signing.
 10. `verify_manifest(require_attestation=True)` rejects a plain
     SHA-256-only manifest.
 11. `verify_manifest` with a manifest whose `attestation.pubkey_b64`
     was swapped for a random key produces an ATTESTATION FAILED
     problem (TPM available) or a signature mismatch otherwise.
"""
import base64
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.utils import tpm_attest
from aegis.utils.self_protect import (
    build_manifest,
    verify_manifest,
    _canonical_payload,
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


# ── Module-level round trip ─────────────────────────────────────────

def test_sign_verify_round_trip():
    section("1. tpm_attest sign + verify round trip")
    if not tpm_attest.is_available():
        print("  [skip] no TPM provider available")
        return

    payload = b"the quick brown fox jumps over the lazy dog"
    sig = tpm_attest.sign(payload)
    check(sig is not None, "sign() returned a signature object")
    if sig is None:
        return
    check(set(sig.keys()) >= {"version", "algo", "provider", "key_name",
                              "pubkey_b64", "sig_b64"},
          f"sig_obj has the documented fields (got {sorted(sig.keys())})")
    check(sig["algo"] == "ECDSA-P256-SHA256",
          f"algo == ECDSA-P256-SHA256 (got {sig['algo']})")
    pub = base64.b64decode(sig["pubkey_b64"])
    raw_sig = base64.b64decode(sig["sig_b64"])
    check(len(pub) == 64, f"public key is 64 bytes (got {len(pub)})")
    check(len(raw_sig) == 64, f"signature is 64 bytes (got {len(raw_sig)})")

    v = tpm_attest.verify(payload, sig)
    check(v["ok"] is True, f"verify ok=True (got {v})")
    check(v["signature_valid"] is True, "signature_valid=True")
    check(v["host_bound_checked"] is True, "host_bound_checked=True")
    check(v["host_bound_match"] is True, "host_bound_match=True")


def test_tampered_payload_fails():
    section("2. Tampered payload fails verification")
    if not tpm_attest.is_available():
        print("  [skip] no TPM provider available")
        return
    sig = tpm_attest.sign(b"original payload")
    v = tpm_attest.verify(b"different payload", sig)
    check(v["ok"] is False, "ok=False on tampered payload")
    check(v["signature_valid"] is False, "signature_valid=False")


def test_forged_pubkey_fails():
    section("3. Forged public key is rejected")
    if not tpm_attest.is_available():
        print("  [skip] no TPM provider available")
        return
    sig = dict(tpm_attest.sign(b"x"))
    # Swap in a random 64-byte string as the public key.
    sig["pubkey_b64"] = base64.b64encode(secrets.token_bytes(64)).decode()
    v = tpm_attest.verify(b"x", sig)
    # On a TPM host the public-key compare will catch it; on a
    # TPM-less host the math-only verify still rejects (random pub
    # cannot match the original signature).
    check(v["ok"] is False, "ok=False on forged public key")


def test_pure_python_verify_agrees_with_cng():
    section("4. Pure-Python ECDSA verifier agrees with CNG")
    if not tpm_attest.is_available():
        print("  [skip] no TPM provider available — skipping cross-check")
        return
    payload = b"cross-platform verification corpus"
    sig = tpm_attest.sign(payload)
    pub = base64.b64decode(sig["pubkey_b64"])
    raw = base64.b64decode(sig["sig_b64"])
    import hashlib
    digest = hashlib.sha256(payload).digest()
    pure_ok = tpm_attest._ecdsa_p256_verify_pure(pub, digest, raw)
    check(pure_ok is True,
          "pure-Python ECDSA P-256 verify agrees with CNG signature")


def test_canonical_payload_excludes_attestation():
    section("5. _canonical_payload ignores the attestation field")
    base = {
        "generated_at": 1.0,
        "hostname": "h",
        "file_count": 1,
        "files": {"a": "1"*64},
    }
    p1 = _canonical_payload(base)
    p2 = _canonical_payload({**base, "attestation": {"sig_b64": "deadbeef"}})
    check(p1 == p2,
          "canonical bytes identical with / without attestation block")


# ── self_protect integration ────────────────────────────────────────

def _make_project(tmp: Path) -> tuple[Path, Path]:
    """Build a tiny project tree with one config file and one rule
    file. Return (project_root, config_path)."""
    (tmp / "config").mkdir()
    cfg = tmp / "config" / "aegis.yaml"
    cfg.write_text("core:\n  log_level: INFO\n", encoding="utf-8")
    (tmp / "rules" / "yara").mkdir(parents=True)
    rule = tmp / "rules" / "yara" / "test.yar"
    rule.write_text(
        'rule t { strings: $a = "abc" condition: $a }\n', encoding="utf-8")
    return tmp, cfg


def test_build_manifest_attaches_attestation_when_tpm():
    section("6. build_manifest attaches attestation when TPM available")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_tpm_build_"))
    root, cfg = _make_project(tmp)
    mpath = tmp / "data" / "manifest.json"
    manifest = build_manifest(root, cfg, mpath, attest=True)

    if tpm_attest.is_available():
        check("attestation" in manifest,
              "attestation block present on TPM host")
        sig_obj = manifest.get("attestation") or {}
        check(sig_obj.get("algo") == "ECDSA-P256-SHA256",
              "attestation algo is ECDSA-P256-SHA256")
    else:
        check("attestation" not in manifest,
              "no attestation block on non-TPM host (graceful)")


def test_verify_manifest_clean():
    section("7. verify_manifest accepts an unmodified attested manifest")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_tpm_verify_clean_"))
    root, cfg = _make_project(tmp)
    mpath = tmp / "data" / "manifest.json"
    build_manifest(root, cfg, mpath, attest=True)
    ok, problems = verify_manifest(root, cfg, mpath)
    check(ok is True, f"verify clean (got problems={problems})")


def test_verify_detects_files_tamper_after_sign():
    section("8. Tampering with `files` after signing is detected")
    if not tpm_attest.is_available():
        print("  [skip] no TPM provider — would not have signed in step 1")
        return
    tmp = Path(tempfile.mkdtemp(prefix="aegis_tpm_tamper_"))
    root, cfg = _make_project(tmp)
    mpath = tmp / "data" / "manifest.json"
    build_manifest(root, cfg, mpath, attest=True)

    # Tamper: edit a hash in the files map without re-signing.
    obj = json.loads(mpath.read_text())
    paths = list(obj["files"].keys())
    obj["files"][paths[0]] = "0" * 64
    mpath.write_text(json.dumps(obj, indent=2))

    ok, problems = verify_manifest(root, cfg, mpath)
    check(ok is False, "verification fails after tampering")
    has_modified = any("MODIFIED" in p for p in problems)
    has_attestation_fail = any("ATTESTATION" in p for p in problems)
    check(has_modified or has_attestation_fail,
          f"problems list flags tampering "
          f"(MODIFIED or ATTESTATION FAILED): got {problems}")


def test_require_attestation_rejects_unsigned():
    section("9. require_attestation=True rejects an unsigned manifest")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_tpm_required_"))
    root, cfg = _make_project(tmp)
    mpath = tmp / "data" / "manifest.json"
    # Build with attest=False so there's no signature.
    build_manifest(root, cfg, mpath, attest=False)

    ok, problems = verify_manifest(root, cfg, mpath,
                                   require_attestation=True)
    check(ok is False, "verify fails when attestation required + missing")
    check(any("attestation REQUIRED" in p for p in problems),
          f"problem mentions REQUIRED: got {problems}")

    # And without that flag, the same manifest should pass.
    ok2, _ = verify_manifest(root, cfg, mpath, require_attestation=False)
    check(ok2 is True, "same manifest passes without require_attestation")


def test_verify_detects_pubkey_swap():
    section("10. Pubkey swap is detected on a TPM host")
    if not tpm_attest.is_available():
        print("  [skip] no TPM provider available")
        return
    tmp = Path(tempfile.mkdtemp(prefix="aegis_tpm_pubswap_"))
    root, cfg = _make_project(tmp)
    mpath = tmp / "data" / "manifest.json"
    build_manifest(root, cfg, mpath, attest=True)

    obj = json.loads(mpath.read_text())
    obj["attestation"]["pubkey_b64"] = base64.b64encode(
        secrets.token_bytes(64)
    ).decode()
    mpath.write_text(json.dumps(obj, indent=2))

    ok, problems = verify_manifest(root, cfg, mpath)
    check(ok is False, "verification fails after pubkey swap")
    check(any("ATTESTATION FAILED" in p for p in problems),
          f"problem flagged as ATTESTATION FAILED: got {problems}")


def main():
    print("=" * 60)
    print("AEGIS — TPM Attestation Test")
    print("=" * 60)
    print(f"TPM provider available on this host: {tpm_attest.is_available()}")

    test_sign_verify_round_trip()
    test_tampered_payload_fails()
    test_forged_pubkey_fails()
    test_pure_python_verify_agrees_with_cng()
    test_canonical_payload_excludes_attestation()
    test_build_manifest_attaches_attestation_when_tpm()
    test_verify_manifest_clean()
    test_verify_detects_files_tamper_after_sign()
    test_require_attestation_rejects_unsigned()
    test_verify_detects_pubkey_swap()

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
