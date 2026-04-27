"""
AEGIS — TPM-Bound Manifest Attestation
=======================================
Signs the integrity manifest with a TPM-backed ECDSA P-256 key so a
stolen `integrity.manifest.json` cannot be replayed on a different
host. The private key never leaves the TPM; the public key is
embedded in the manifest, and verification chains through the
host's own TPM whenever it's available.

Backend
-------
Windows: NCrypt + the **Microsoft Platform Crypto Provider** — the
TPM-backed key store that ships with Windows 8+. No `tpm2-pytss`
dependency. The persistent key is named `AEGIS-MANIFEST-V1`.

Linux/macOS: graceful no-op for now. `is_available()` returns False
and `sign()` returns None. A future track can plug in tpm2-tss
(`/dev/tpmrm0`) without changing the public surface here.

Verification levels
-------------------
1. No attestation block in the manifest → SHA-256 only (legacy).
2. Block present + TPM available → re-export this host's public key,
   compare to the stored one, then verify the signature. Strongest.
3. Block present + TPM unavailable → signature verify against the
   bundled public key only. Useful but not host-bound.

Wire format (sig_obj)
---------------------
    {
      "version": 1,
      "algo": "ECDSA-P256-SHA256",
      "provider": "Microsoft Platform Crypto Provider",
      "key_name": "AEGIS-MANIFEST-V1",
      "pubkey_b64": "<base64 of 64-byte X||Y>",
      "sig_b64": "<base64 of 64-byte r||s>"
    }
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wintypes
import hashlib
import logging
import platform
from typing import Optional

logger = logging.getLogger("aegis.utils.tpm_attest")


_PROVIDER_PLATFORM = "Microsoft Platform Crypto Provider"
_PROVIDER_SOFTWARE = "Microsoft Software Key Storage Provider"   # fallback / tests
_KEY_NAME = "AEGIS-MANIFEST-V1"
_ALG_ECDSA_P256 = "ECDSA_P256"
_BLOB_ECCPUBLIC = "ECCPUBLICBLOB"

# BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345 ('ECS1' in little-endian).
_ECDSA_P256_PUB_MAGIC = 0x31534345

NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080
NTE_EXISTS = 0x8009000F


# ── Public API ──────────────────────────────────────────────────────

def is_available() -> bool:
    """True when the host has a callable Platform Crypto Provider.

    Cheap probe — opens the provider and immediately closes it. We do
    NOT exercise key creation here; that happens lazily on the first
    `sign()` call so a verify-only host without write privilege isn't
    forced into a key-create round trip.
    """
    if platform.system().lower() != "windows":
        return False
    try:
        provider = _open_provider(_PROVIDER_PLATFORM)
        if provider is None:
            return False
        _ncrypt_free_object(provider)
        return True
    except Exception as e:
        logger.debug(f"tpm_attest: probe failed: {e}")
        return False


def sign(payload: bytes) -> Optional[dict]:
    """Sign `payload` with the TPM-bound key. Creates the persistent
    key on first use. Returns the signature object (see module
    docstring) or None on failure.
    """
    if platform.system().lower() != "windows":
        return None
    try:
        provider = _open_provider(_PROVIDER_PLATFORM)
        if provider is None:
            return None
        try:
            key = _open_or_create_key(provider, _KEY_NAME, _ALG_ECDSA_P256)
            try:
                pub_xy = _export_public_xy(key)
                digest = hashlib.sha256(payload).digest()
                sig = _sign_hash(key, digest)
            finally:
                _ncrypt_free_object(key)
        finally:
            _ncrypt_free_object(provider)
    except Exception as e:
        logger.warning(f"tpm_attest: sign failed: {e}")
        return None

    return {
        "version": 1,
        "algo": "ECDSA-P256-SHA256",
        "provider": _PROVIDER_PLATFORM,
        "key_name": _KEY_NAME,
        "pubkey_b64": base64.b64encode(pub_xy).decode("ascii"),
        "sig_b64":    base64.b64encode(sig).decode("ascii"),
    }


def verify(payload: bytes, sig_obj: dict) -> dict:
    """Verify a signature object against `payload`. Returns a dict
    with the outcome. Never raises.

        {
          "ok": bool,                  # the bottom-line answer
          "signature_valid": bool,     # ECDSA verify succeeded
          "host_bound_checked": bool,  # we managed to compare TPM pubkey
          "host_bound_match": bool,    # if checked, did pubkey match?
          "reason": str,
        }
    """
    out = {
        "ok": False,
        "signature_valid": False,
        "host_bound_checked": False,
        "host_bound_match": False,
        "reason": "",
    }
    try:
        pub_xy = base64.b64decode(sig_obj["pubkey_b64"])
        sig    = base64.b64decode(sig_obj["sig_b64"])
    except Exception as e:
        out["reason"] = f"malformed sig_obj: {e}"
        return out

    if len(pub_xy) != 64 or len(sig) != 64:
        out["reason"] = "wrong pubkey/sig length"
        return out

    digest = hashlib.sha256(payload).digest()

    # Always run the math-only verify with the bundled public key.
    try:
        out["signature_valid"] = _bcrypt_verify(pub_xy, digest, sig)
    except Exception as e:
        out["reason"] = f"signature verify failed: {e}"
        return out

    # When TPM is available, check that the manifest's bundled
    # public key matches what THIS host's TPM exports — that's the
    # piece that turns a generic forgeable signature into a host-
    # bound attestation.
    if is_available():
        try:
            provider = _open_provider(_PROVIDER_PLATFORM)
            if provider is not None:
                try:
                    key = _open_or_create_key(provider, _KEY_NAME, _ALG_ECDSA_P256)
                    try:
                        host_pub = _export_public_xy(key)
                    finally:
                        _ncrypt_free_object(key)
                finally:
                    _ncrypt_free_object(provider)
                out["host_bound_checked"] = True
                out["host_bound_match"] = (host_pub == pub_xy)
        except Exception as e:
            out["reason"] = (out["reason"]
                             or f"host-bound check failed: {e}")

    if out["host_bound_checked"]:
        out["ok"] = out["signature_valid"] and out["host_bound_match"]
        if not out["ok"] and not out["reason"]:
            out["reason"] = (
                "signature mismatch" if not out["signature_valid"]
                else "manifest pubkey does not match this host's TPM key"
            )
    else:
        # Best-effort: signature math is OK but we can't host-bind.
        out["ok"] = out["signature_valid"]
        if out["ok"] and not out["reason"]:
            out["reason"] = "signature valid; host-binding NOT verified (no TPM)"

    return out


# ── ctypes plumbing ─────────────────────────────────────────────────
# Loaded lazily so the module import works on non-Windows hosts.

_ncrypt = None
_bcrypt = None


def _load_libs():
    global _ncrypt, _bcrypt
    if _ncrypt is None:
        _ncrypt = ctypes.WinDLL("ncrypt.dll")
        _bcrypt = ctypes.WinDLL("bcrypt.dll")


def _check(status: int, label: str):
    """SECURITY_STATUS / NTSTATUS: 0 == success."""
    if status != 0:
        raise OSError(f"{label} failed: 0x{status & 0xFFFFFFFF:08x}")


def _open_provider(name: str):
    _load_libs()
    h = wintypes.HANDLE()
    rc = _ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(h), ctypes.c_wchar_p(name), 0,
    )
    if rc != 0:
        return None
    return h


def _ncrypt_free_object(handle):
    if handle is None:
        return
    try:
        _ncrypt.NCryptFreeObject(handle)
    except Exception:
        pass


def _open_or_create_key(provider, key_name: str, algo: str):
    _load_libs()
    h = wintypes.HANDLE()
    rc = _ncrypt.NCryptOpenKey(
        provider, ctypes.byref(h),
        ctypes.c_wchar_p(key_name), 0, 0,
    )
    if rc == 0:
        return h
    # Not found — create it.
    rc = _ncrypt.NCryptCreatePersistedKey(
        provider, ctypes.byref(h),
        ctypes.c_wchar_p(algo),
        ctypes.c_wchar_p(key_name),
        0, 0,
    )
    _check(rc, "NCryptCreatePersistedKey")
    rc = _ncrypt.NCryptFinalizeKey(h, 0)
    _check(rc, "NCryptFinalizeKey")
    return h


def _export_public_xy(key) -> bytes:
    """Export the public key as ECCPUBLICBLOB and return the raw
    X||Y bytes (64 for P-256). Validates the magic to catch a key
    created with the wrong algorithm.
    """
    _load_libs()
    cb = wintypes.DWORD(0)
    rc = _ncrypt.NCryptExportKey(
        key, None,
        ctypes.c_wchar_p(_BLOB_ECCPUBLIC),
        None, None, 0, ctypes.byref(cb), 0,
    )
    _check(rc, "NCryptExportKey (size)")
    buf = (ctypes.c_ubyte * cb.value)()
    rc = _ncrypt.NCryptExportKey(
        key, None,
        ctypes.c_wchar_p(_BLOB_ECCPUBLIC),
        None, buf, cb.value, ctypes.byref(cb), 0,
    )
    _check(rc, "NCryptExportKey (read)")
    blob = bytes(buf[:cb.value])
    # BCRYPT_ECCKEY_BLOB header: dwMagic (4) + cbKey (4) = 8 bytes
    if len(blob) < 8 + 64:
        raise OSError(f"unexpected ECCPUBLICBLOB length {len(blob)}")
    magic = int.from_bytes(blob[0:4], "little")
    if magic != _ECDSA_P256_PUB_MAGIC:
        raise OSError(f"unexpected ECC magic 0x{magic:08x}")
    return blob[8:8 + 64]


def _sign_hash(key, digest: bytes) -> bytes:
    _load_libs()
    cb = wintypes.DWORD(0)
    rc = _ncrypt.NCryptSignHash(
        key, None,
        (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest),
        len(digest),
        None, 0, ctypes.byref(cb), 0,
    )
    _check(rc, "NCryptSignHash (size)")
    sig_buf = (ctypes.c_ubyte * cb.value)()
    rc = _ncrypt.NCryptSignHash(
        key, None,
        (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest),
        len(digest),
        sig_buf, cb.value, ctypes.byref(cb), 0,
    )
    _check(rc, "NCryptSignHash (sign)")
    return bytes(sig_buf[:cb.value])


def _bcrypt_verify(pub_xy: bytes, digest: bytes, sig: bytes) -> bool:
    """Standalone (no TPM needed) signature verification using BCrypt.

    Used for the math-only check that runs even on Linux / macOS /
    after a TPM clear. Builds a BCRYPT_ECCKEY_BLOB on the fly.
    """
    if platform.system().lower() != "windows":
        # Linux/macOS path: implement ECDSA P-256 verify in pure
        # Python. We need this so verifying an attested manifest on
        # a non-Windows host still succeeds at the signature level.
        return _ecdsa_p256_verify_pure(pub_xy, digest, sig)
    _load_libs()
    blob = (
        _ECDSA_P256_PUB_MAGIC.to_bytes(4, "little")
        + (32).to_bytes(4, "little")
        + pub_xy
    )
    blob_buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)

    alg = wintypes.HANDLE()
    rc = _bcrypt.BCryptOpenAlgorithmProvider(
        ctypes.byref(alg),
        ctypes.c_wchar_p("ECDSA_P256"),
        None, 0,
    )
    _check(rc, "BCryptOpenAlgorithmProvider")
    try:
        key = wintypes.HANDLE()
        rc = _bcrypt.BCryptImportKeyPair(
            alg, None,
            ctypes.c_wchar_p(_BLOB_ECCPUBLIC),
            ctypes.byref(key),
            blob_buf, len(blob), 0,
        )
        _check(rc, "BCryptImportKeyPair")
        try:
            rc = _bcrypt.BCryptVerifySignature(
                key, None,
                (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest),
                len(digest),
                (ctypes.c_ubyte * len(sig)).from_buffer_copy(sig),
                len(sig),
                0,
            )
            return rc == 0
        finally:
            _bcrypt.BCryptDestroyKey(key)
    finally:
        _bcrypt.BCryptCloseAlgorithmProvider(alg, 0)


# ── Pure-Python ECDSA P-256 verify (Linux/macOS verify-side path) ──
# Standard NIST P-256 parameters. Used only for verification, never
# for signing. Dependency-free so a CI host without a TPM can still
# verify an attested manifest.

_P256_P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_A  = -3 % _P256_P
_P256_B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _inv_mod(a: int, m: int) -> int:
    return pow(a, -1, m)


def _point_double(P):
    if P is None:
        return None
    x, y = P
    if y == 0:
        return None
    s = (3 * x * x + _P256_A) * _inv_mod(2 * y, _P256_P) % _P256_P
    x3 = (s * s - 2 * x) % _P256_P
    y3 = (s * (x - x3) - y) % _P256_P
    return (x3, y3)


def _point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        return _point_double(P)
    s = (y2 - y1) * _inv_mod((x2 - x1) % _P256_P, _P256_P) % _P256_P
    x3 = (s * s - x1 - x2) % _P256_P
    y3 = (s * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _scalar_mul(k: int, P):
    R = None
    addend = P
    while k:
        if k & 1:
            R = _point_add(R, addend)
        addend = _point_double(addend)
        k >>= 1
    return R


def _ecdsa_p256_verify_pure(pub_xy: bytes, digest: bytes, sig: bytes) -> bool:
    if len(pub_xy) != 64 or len(sig) != 64 or len(digest) != 32:
        return False
    Qx = int.from_bytes(pub_xy[:32], "big")
    Qy = int.from_bytes(pub_xy[32:], "big")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    e = int.from_bytes(digest, "big")
    w = _inv_mod(s, _P256_N)
    u1 = (e * w) % _P256_N
    u2 = (r * w) % _P256_N
    G = (_P256_GX, _P256_GY)
    Q = (Qx, Qy)
    P1 = _scalar_mul(u1, G)
    P2 = _scalar_mul(u2, Q)
    R = _point_add(P1, P2)
    if R is None:
        return False
    return (R[0] % _P256_N) == r


# ── Test/maintenance hook ──────────────────────────────────────────

def delete_persistent_key() -> bool:
    """Delete the persistent TPM key (next sign() will recreate it).
    Used by the maintenance CLI when an operator rotates the key."""
    if platform.system().lower() != "windows":
        return False
    try:
        provider = _open_provider(_PROVIDER_PLATFORM)
        if provider is None:
            return False
        try:
            key = wintypes.HANDLE()
            rc = _ncrypt.NCryptOpenKey(
                provider, ctypes.byref(key),
                ctypes.c_wchar_p(_KEY_NAME), 0, 0,
            )
            if rc != 0:
                return True   # already absent
            rc = _ncrypt.NCryptDeleteKey(key, 0)
            return rc == 0
        finally:
            _ncrypt_free_object(provider)
    except Exception:
        return False


__all__ = [
    "is_available",
    "sign",
    "verify",
    "delete_persistent_key",
]
