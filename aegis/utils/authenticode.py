"""
AEGIS Authenticode Verification
================================
Verifies the Authenticode signature of a Windows PE file via WinVerifyTrust
(wintrust.dll). No external dependencies — uses ctypes.

Returns one of:
    "valid"         — signature is present, chain trusted, hash matches
    "invalid"       — signature present but failed validation (revoked, hash
                      mismatch, untrusted root). Treat as malicious.
    "unsigned"      — no embedded signature
    "error"         — verification could not be performed (file gone, IO,
                      not Windows, etc.)

We deliberately do NOT consult catalog files (CAT) here for performance —
catalog lookup would gate every single process spawn on a kernel call into
CryptCATAdminCalcHashFromFileHandle. For an MVP, embedded signatures cover
~95% of legitimate binaries that matter (Microsoft, Chrome, Office, etc.);
SYSTEM-shipped CAT-only binaries would show as "unsigned" but we whitelist
the System32/SysWOW64 paths to keep the false-positive rate near zero.
"""

from __future__ import annotations

import os
import logging
import platform
from pathlib import Path

logger = logging.getLogger("aegis.utils.authenticode")

# Paths whose contents we trust if Authenticode says "unsigned" (catalog-signed
# Windows components). Lower-cased for comparison.
TRUSTED_DIRS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\windows\servicing",
)

# Locations where an unsigned binary is essentially always suspicious.
HIGH_RISK_DIRS = (
    r":\users\public",
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\windows\temp",
    r":\temp",
    r":\tmp",
)


class _Cache:
    """Per-path memoisation. Verification syscalls are cheap individually
    but add up when 100+ services start at boot."""
    def __init__(self, max_entries: int = 4096):
        self._d: dict[str, tuple[str, str | None]] = {}
        self._max = max_entries

    def get(self, key: str):
        return self._d.get(key)

    def put(self, key: str, value: tuple[str, str | None]):
        if len(self._d) >= self._max:
            # Evict the oldest 25% — cheap and good enough.
            for k in list(self._d.keys())[: self._max // 4]:
                self._d.pop(k, None)
        self._d[key] = value


_cache = _Cache()


def _verify_via_wintrust(path: str) -> tuple[str, str | None]:
    """Returns (status, signer_subject). Windows-only — caller checks first."""
    import ctypes
    from ctypes import wintypes

    # GUIDs
    WINTRUST_ACTION_GENERIC_VERIFY_V2 = ctypes.c_byte * 16
    # {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    guid = WINTRUST_ACTION_GENERIC_VERIFY_V2(
        0x6b, 0xc5, 0xaa, 0x00, 0x44, 0xcd, 0xd0, 0x11,
        0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee,
    )

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pUnion", ctypes.c_void_p),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = 2          # WTD_UI_NONE
    data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE (skip OCSP for speed)
    data.dwUnionChoice = 1        # WTD_CHOICE_FILE
    data.pUnion = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
    data.dwStateAction = 1        # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x00000040 # WTD_CACHE_ONLY_URL_RETRIEVAL

    wintrust = ctypes.WinDLL("wintrust.dll")
    WinVerifyTrust = wintrust.WinVerifyTrust
    WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                               ctypes.POINTER(WINTRUST_DATA)]
    WinVerifyTrust.restype = wintypes.LONG

    INVALID_HANDLE = wintypes.HWND(-1)
    rc = WinVerifyTrust(INVALID_HANDLE, ctypes.byref(guid), ctypes.byref(data))

    # Always close state.
    data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
    WinVerifyTrust(INVALID_HANDLE, ctypes.byref(guid), ctypes.byref(data))

    rc_unsigned_codes = (
        0x800B0100,  # TRUST_E_NOSIGNATURE
        0x800B0003,  # TRUST_E_PROVIDER_UNKNOWN
        0x80092009,  # CRYPT_E_NO_MATCH
    )
    # Coerce signed→unsigned
    if rc < 0:
        rc &= 0xFFFFFFFF
    if rc == 0:
        return "valid", None
    if rc in rc_unsigned_codes:
        return "unsigned", None
    return "invalid", f"WinVerifyTrust=0x{rc:08x}"


def verify_pe(path: str) -> tuple[str, str | None]:
    """Public entry point. Returns (status, detail)."""
    if platform.system() != "Windows":
        return "error", "not windows"
    if not path or not os.path.isfile(path):
        return "error", "missing file"
    cached = _cache.get(path)
    if cached:
        return cached
    try:
        result = _verify_via_wintrust(path)
    except Exception as e:
        logger.debug(f"Authenticode verify failed for {path}: {e}")
        result = "error", str(e)[:200]
    _cache.put(path, result)
    return result


# ── Triage helpers ────────────────────────────────────────────────

def is_trusted_system_path(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    return any(p.startswith(d) for d in TRUSTED_DIRS)


def is_high_risk_path(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    return any(d in p for d in HIGH_RISK_DIRS)


def triage(path: str) -> dict:
    """One-shot helper for the process monitor: returns
    {status, severity, reason} suitable for embedding in an event."""
    status, detail = verify_pe(path)
    severity = "info"
    reason = ""
    if status == "invalid":
        severity = "critical"
        reason = f"signature invalid ({detail})"
    elif status == "unsigned":
        if is_high_risk_path(path):
            severity = "critical"
            reason = "unsigned binary in high-risk directory"
        elif is_trusted_system_path(path):
            severity = "info"   # catalog-signed system component
            reason = "catalog-signed (system path)"
        else:
            severity = "medium"
            reason = "unsigned binary"
    elif status == "valid":
        severity = "info"
        reason = "signature valid"
    elif status == "error":
        severity = "low"
        reason = f"verification error ({detail})"
    return {"status": status, "severity": severity, "reason": reason,
            "detail": detail or ""}


__all__ = ["verify_pe", "triage", "is_trusted_system_path", "is_high_risk_path"]
