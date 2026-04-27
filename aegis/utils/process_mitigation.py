"""
AEGIS Self-Protection — Process Mitigation Policies (Windows)
=============================================================
Calls `SetProcessMitigationPolicy` early in bootstrap to harden AEGIS's
own surface area against userland exploitation. This is Microsoft's
documented per-process attack-surface-reduction API; commercial EDR
agents apply the same set to their own processes.

What's applied (safe-by-default bundle)
---------------------------------------
  ExtensionPointDisable    Blocks legacy AppInit_DLLs / shell-extensions
                           from being loaded into our process — closes a
                           classic Windows persistence-via-DLL-injection
                           vector that would otherwise let a malicious
                           DLL ride into AEGIS at startup.
  StrictHandleCheck        Raises an exception on any invalid handle
                           reference. Catches use-after-close bugs that
                           are otherwise silent and abusable.
  ImageLoadPolicy          NoRemoteImages       — refuse to load DLLs
                                                   from UNC / SMB paths.
                           NoLowMandatoryLabel  — refuse to load DLLs
                                                   that live in
                                                   low-integrity dirs.
                           PreferSystem32       — system32 wins DLL
                                                   search-order ties.
  FontDisable              Blocks loading of non-system fonts (historic
                           Win32k font-parser CVE class).

What's deliberately NOT applied
-------------------------------
  BinarySignaturePolicy    Setting MicrosoftSignedOnly would refuse
                           to load every non-MS-signed DLL — including
                           numpy, scikit-learn, yara-python, psutil.
                           That's a self-inflicted DoS, not hardening.
  ControlFlowGuard         Compile/link-time. Python.exe ships with it
                           where supported; we can't toggle at runtime.
  ASLR (most flags)        Set by the loader at process creation.
                           SetProcessMitigationPolicy can't add them
                           after the fact for our parent process.
  PPL (Protected Process)  Requires a Microsoft-issued AV/EDR cert.
                           Out of scope for an open-source defender.
  DEP                      Already mandatory on x64 Windows.

Aggressive bundle (opt-in via `aggressive: true`)
-------------------------------------------------
  DynamicCodePolicy        ProhibitDynamicCode — blocks any thread
                           from generating executable code at runtime.
                           High security value (kills shellcode
                           reflective-load) but **breaks** ctypes
                           callbacks in some third-party libs and any
                           future LLM triage that uses a JIT-backed
                           inference runtime.
  ChildProcessPolicy       NoChildProcessCreation — would prevent
                           AEGIS spawning subprocesses. **Breaks**
                           `--harden`, persistence monitor's
                           `systemctl` calls, hardening_recheck's
                           `Get-MpPreference`, and several CLI
                           subcommands. Only enable when running the
                           main service in lockdown mode and using a
                           separate process for those CLI tasks.

Both irrevocable: once set on the process, they cannot be turned off
without restart.
"""

from __future__ import annotations

import logging
import platform
from typing import Optional

logger = logging.getLogger("aegis.utils.process_mitigation")


# ── Policy identifiers (PROCESS_MITIGATION_POLICY enum) ──────────────
# Defined in <processthreadsapi.h>; values are stable across SDK
# versions because they're exposed to userland as a contract.
_POLICY_DEP                 = 0
_POLICY_ASLR                = 1
_POLICY_DYNAMIC_CODE        = 2
_POLICY_STRICT_HANDLE_CHECK = 3
_POLICY_EXTENSION_POINT     = 6
_POLICY_FONT_DISABLE        = 9
_POLICY_IMAGE_LOAD          = 10
_POLICY_CHILD_PROCESS       = 13


# ── Policy bit values (each policy struct is a single DWORD) ─────────
# ExtensionPointDisable
_EXT_POINT_DISABLE_BIT      = 0x1

# StrictHandleCheck
_HANDLE_RAISE_EXCEPTION     = 0x1
_HANDLE_PERMANENT           = 0x2

# ImageLoad
_IMAGE_NO_REMOTE            = 0x1
_IMAGE_NO_LOW_LABEL         = 0x2
_IMAGE_PREFER_SYSTEM32      = 0x4

# FontDisable
_FONT_DISABLE_NON_SYSTEM    = 0x1

# DynamicCode (aggressive)
_DYNCODE_PROHIBIT           = 0x1

# ChildProcess (aggressive)
_CHILDPROC_NO_CREATE        = 0x1


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _safe_bundle() -> list[tuple[int, int, str]]:
    """(policy_id, dword_value, label) for the always-on bundle."""
    return [
        (_POLICY_EXTENSION_POINT, _EXT_POINT_DISABLE_BIT,
         "extension_point_disable"),
        (_POLICY_STRICT_HANDLE_CHECK,
         _HANDLE_RAISE_EXCEPTION | _HANDLE_PERMANENT,
         "strict_handle_check"),
        (_POLICY_IMAGE_LOAD,
         _IMAGE_NO_REMOTE | _IMAGE_NO_LOW_LABEL | _IMAGE_PREFER_SYSTEM32,
         "image_load_restrictions"),
        (_POLICY_FONT_DISABLE, _FONT_DISABLE_NON_SYSTEM,
         "non_system_font_disable"),
    ]


def _aggressive_bundle() -> list[tuple[int, int, str]]:
    """(policy_id, dword_value, label) for opt-in aggressive policies.

    These break legitimate AEGIS behaviour today; only enable when the
    operator has separated the lockdown service from the CLI surface.
    """
    return [
        (_POLICY_DYNAMIC_CODE, _DYNCODE_PROHIBIT,
         "prohibit_dynamic_code"),
        (_POLICY_CHILD_PROCESS, _CHILDPROC_NO_CREATE,
         "no_child_process"),
    ]


def _set_one(policy_id: int, dword_value: int) -> Optional[int]:
    """Apply one policy. Returns None on success, Win32 error code on
    failure. Win32 only; raises on import elsewhere — guard with
    `_is_windows()` before calling.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    SetProcessMitigationPolicy = kernel32.SetProcessMitigationPolicy
    SetProcessMitigationPolicy.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    SetProcessMitigationPolicy.restype = wintypes.BOOL

    val = ctypes.c_uint32(dword_value)
    ok = SetProcessMitigationPolicy(
        policy_id, ctypes.byref(val), ctypes.sizeof(val),
    )
    if ok:
        return None
    return ctypes.get_last_error()


def apply_mitigations(*, aggressive: bool = False) -> dict:
    """Apply the safe-by-default bundle (and aggressive set when
    requested). Returns a structured report so the caller can publish
    an audit event.

    Report shape:
        {
            "platform": "windows" | "linux" | ...,
            "applied": [label, ...],
            "failed":  [{"label": str, "winerror": int}, ...],
            "skipped": [{"label": str, "reason": str}, ...],
            "aggressive": bool,
        }
    """
    report: dict = {
        "platform": platform.system().lower(),
        "applied": [],
        "failed": [],
        "skipped": [],
        "aggressive": aggressive,
    }

    if not _is_windows():
        for _, _, label in _safe_bundle() + _aggressive_bundle():
            report["skipped"].append(
                {"label": label, "reason": "not on Windows"}
            )
        return report

    bundles = list(_safe_bundle())
    if aggressive:
        bundles.extend(_aggressive_bundle())

    for policy_id, dword_value, label in bundles:
        try:
            err = _set_one(policy_id, dword_value)
        except Exception as e:
            report["failed"].append({
                "label": label, "winerror": -1, "error": str(e),
            })
            logger.warning(
                f"process mitigation '{label}' raised: {e}"
            )
            continue
        if err is None:
            report["applied"].append(label)
            logger.info(f"process mitigation applied: {label}")
        else:
            # ERROR_ACCESS_DENIED (5) is the common case for policies
            # already permanently set (e.g. by the parent process or a
            # group policy) — log at debug, not warning.
            level = logging.DEBUG if err == 5 else logging.WARNING
            logger.log(level,
                f"process mitigation '{label}' failed: winerror={err}"
            )
            report["failed"].append({
                "label": label, "winerror": err,
            })

    return report
