"""
AEGIS — AMSI Client (Windows Antimalware Scan Interface)
=========================================================
Submits buffers to the host's configured AMSI providers (Windows
Defender by default) and publishes a `detection.amsi` event when
the verdict is malware. The AmsiScanner subscribes to file.create
and file.modify events for script-class extensions and scans the
file content before execution.

What this is — and what it isn't
--------------------------------
AMSI has two roles:

  * **Provider** — register as `IAntimalwareProvider` via COM, ship
    a signed DLL that's loaded into every PowerShell / Office / WMI
    process, see every scan request system-wide. This is what
    Defender, CrowdStrike, S1 etc. do. Requires Authenticode signing,
    PPL, registry CLSID registration. **Out of scope here.**
  * **Client** — call `AmsiScanBuffer` from our own process. Defender
    is the default provider and runs the buffer through its engine.
    We get the verdict. **This is what AEGIS does.**

Client coverage is partial: we only see buffers we hand to AMSI, not
every PowerShell script-block running on the host. But combined with
the existing FIM events for `.ps1`, `.vbs`, `.js`, etc., it's a
material upgrade — every script written to a watched path gets
Defender's verdict before it can execute.

For full system-wide PowerShell visibility, ETW subscription to
`Microsoft-Windows-PowerShell` (Event ID 4104, Script Block Logging)
+ `Microsoft-Antimalware-Scan-Interface` is the right next step —
that's R&D backlog item #4 part 2 (deferred).

Threat-model caveats
--------------------
* If Defender is disabled on this host, AMSI returns
  `AMSI_RESULT_NOT_DETECTED` for everything. We log this at
  `start()` so the operator knows their AMSI coverage is dead.
* Verdict reflects whatever provider the host has. AEGIS does not
  ship its own AMSI signatures; we rely on the OS-provided engine.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import threading
from pathlib import Path
from typing import Optional

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.detection.amsi")


# AMSI_RESULT enum from amsi.h. Anything ≥ AMSI_RESULT_DETECTED is malware.
AMSI_RESULT_CLEAN = 0
AMSI_RESULT_NOT_DETECTED = 1
AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384      # 0x4000
AMSI_RESULT_BLOCKED_BY_ADMIN_END   = 20479      # 0x4FFF
AMSI_RESULT_DETECTED = 32768                    # 0x8000


def _is_malware(result: int) -> bool:
    return result >= AMSI_RESULT_DETECTED


def _is_blocked_by_admin(result: int) -> bool:
    return AMSI_RESULT_BLOCKED_BY_ADMIN_START <= result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END


# Default extension allow-list. AMSI's design target is interpreted
# script content; binary executables go through Defender's regular
# real-time scan and aren't useful to double-scan via AMSI.
_DEFAULT_SCRIPT_EXTENSIONS: tuple[str, ...] = (
    ".ps1", ".psm1", ".psd1", ".ps1xml",
    ".vbs", ".vbe", ".vba", ".vbscript",
    ".js", ".jse",
    ".wsf", ".wsh",
    ".bat", ".cmd",
    ".hta",
    ".lnk",
)


# ── AMSI client (thin ctypes wrapper) ───────────────────────────────

class AmsiClient:
    """ctypes wrapper around `amsi.dll`. Lazy-loads the library on
    first scan so module import works on Linux / macOS / Windows
    versions without AMSI."""

    def __init__(self, app_name: str = "AEGIS-EDR"):
        self.app_name = app_name
        self._available = False
        self._amsi = None
        self._context = None
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self._available

    def open(self) -> bool:
        """Initialize the AMSI context. Returns True on success."""
        if platform.system().lower() != "windows":
            return False
        try:
            import ctypes
            import ctypes.wintypes as wintypes
            self._amsi = ctypes.WinDLL("amsi.dll")
        except OSError as e:
            logger.warning(f"AmsiClient: could not load amsi.dll: {e}")
            return False
        try:
            self._amsi.AmsiInitialize.argtypes = [
                ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p),
            ]
            self._amsi.AmsiInitialize.restype = ctypes.c_long  # HRESULT
            self._amsi.AmsiUninitialize.argtypes = [ctypes.c_void_p]
            self._amsi.AmsiUninitialize.restype = None
            self._amsi.AmsiScanBuffer.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                ctypes.c_wchar_p, ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_int),
            ]
            self._amsi.AmsiScanBuffer.restype = ctypes.c_long
        except AttributeError as e:
            logger.warning(f"AmsiClient: amsi.dll missing expected symbol: {e}")
            return False

        ctx = ctypes.c_void_p()
        hr = self._amsi.AmsiInitialize(self.app_name, ctypes.byref(ctx))
        if hr != 0:
            logger.warning(f"AmsiClient: AmsiInitialize failed HRESULT=0x{hr & 0xFFFFFFFF:08x}")
            return False
        self._context = ctx
        self._available = True
        logger.info(f"AmsiClient: initialised (app={self.app_name})")
        return True

    def close(self):
        if self._amsi is not None and self._context is not None:
            try:
                self._amsi.AmsiUninitialize(self._context)
            except Exception:
                pass
        self._context = None
        self._available = False

    def scan_buffer(self, buf: bytes, content_name: str = "") -> dict:
        """Scan `buf`. Returns:
            {"available": bool, "result": int, "is_malware": bool,
             "is_blocked_admin": bool, "name": str}
        On any failure, `available=False` and `result=-1`.
        """
        out = {
            "available": False,
            "result": -1,
            "is_malware": False,
            "is_blocked_admin": False,
            "name": content_name or "",
        }
        if not self._available or self._amsi is None or self._context is None:
            return out
        if not buf:
            out["available"] = True
            out["result"] = AMSI_RESULT_NOT_DETECTED
            return out

        import ctypes
        result = ctypes.c_int(0)
        # AmsiScanBuffer is documented thread-safe with the same
        # context, but we serialise to avoid surprises with the
        # session pointer (we don't use sessions).
        with self._lock:
            buf_arr = (ctypes.c_ubyte * len(buf)).from_buffer_copy(buf)
            hr = self._amsi.AmsiScanBuffer(
                self._context,
                ctypes.cast(buf_arr, ctypes.c_void_p),
                len(buf),
                content_name or None,
                None,
                ctypes.byref(result),
            )
        if hr != 0:
            logger.debug(
                f"AmsiClient: AmsiScanBuffer HRESULT=0x{hr & 0xFFFFFFFF:08x}"
            )
            return out

        r = int(result.value)
        out.update({
            "available": True,
            "result": r,
            "is_malware": _is_malware(r),
            "is_blocked_admin": _is_blocked_by_admin(r),
        })
        return out


# ── Scanner that bridges FIM file events into AMSI ──────────────────

class AmsiScanner:
    """Subscribes to file.create / file.modify events for script
    extensions; reads the file, runs AMSI, publishes a detection
    event when AMSI says malware."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", True))
        self.app_name = str(self.config.get("app_name", "AEGIS-EDR"))
        self.max_file_mb = int(self.config.get("max_file_size_mb", 16))
        self.publish_clean = bool(self.config.get("publish_clean_results", False))
        exts = self.config.get("extensions") or list(_DEFAULT_SCRIPT_EXTENSIONS)
        self.extensions = tuple(e.lower() if e.startswith(".") else f".{e.lower()}"
                                for e in exts)
        # Test/DI hook — caller can pass an AmsiClient stand-in.
        self._client: Optional[AmsiClient] = self.config.get("client")
        self._running = False

    def start(self):
        if not self.enabled:
            logger.info("AmsiScanner: disabled in config")
            return
        if self._client is None:
            self._client = AmsiClient(app_name=self.app_name)
            opened = self._client.open()
            if not opened:
                logger.info(
                    "AmsiScanner: AMSI unavailable (non-Windows or amsi.dll "
                    "missing) — scanner disabled"
                )
                self.enabled = False
                return
        # AMSI's brain is whatever provider the host runs (Defender by
        # default). Probe with the EICAR string — if Defender is live
        # this MUST come back as malware. If not, AMSI is hot-wired
        # to a no-op provider and operators should know.
        probe = self._client.scan_buffer(EICAR_TEST_STRING.encode("ascii"),
                                         content_name="aegis-amsi-probe")
        if probe.get("is_malware"):
            logger.info("AmsiScanner: AMSI provider responsive (EICAR detected)")
        else:
            logger.warning(
                "AmsiScanner: AMSI provider did NOT detect EICAR "
                f"(result={probe.get('result')}). The host's AV may "
                "be disabled or AMSI is wired to a no-op provider."
            )

        self.bus.subscribe("file.create", self._on_file_event)
        self.bus.subscribe("file.modify", self._on_file_event)
        self._running = True
        logger.info(
            f"AmsiScanner started "
            f"(extensions={','.join(self.extensions)}, "
            f"max_size={self.max_file_mb} MB)"
        )

    def stop(self):
        self._running = False
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass

    def _on_file_event(self, event: Event):
        if not self._running:
            return
        path = (event.data or {}).get("path") or (event.data or {}).get("filepath")
        if not path:
            return
        if not str(path).lower().endswith(self.extensions):
            return
        try:
            self.scan_path(str(path), trigger=event)
        except Exception as e:
            logger.debug(f"AmsiScanner: scan_path failed for {path}: {e}")

    def scan_path(self, path: str, *,
                  trigger: Optional[Event] = None) -> Optional[dict]:
        """Read `path`, run AMSI, publish if malware. Returns the AMSI
        result dict (or None if the file was unreadable / oversized)."""
        if self._client is None:
            return None
        p = Path(path)
        if not p.exists():
            return None
        try:
            size = p.stat().st_size
        except OSError:
            return None
        if size > self.max_file_mb * 1024 * 1024:
            logger.debug(f"AmsiScanner: skipping {path} ({size} bytes > limit)")
            return None
        try:
            buf = p.read_bytes()
        except OSError as e:
            logger.debug(f"AmsiScanner: read failed {path}: {e}")
            return None

        result = self._client.scan_buffer(buf, content_name=str(path))
        sha256 = hashlib.sha256(buf).hexdigest()
        result["sha256"] = sha256
        result["size"] = size
        result["path"] = str(path)

        # Publish only on malware verdict by default — clean scans
        # would flood the bus. Operators who want full coverage can
        # set `publish_clean_results: true`.
        if result.get("is_malware"):
            self._publish(result, trigger, severity=Severity.HIGH)
        elif result.get("is_blocked_admin"):
            self._publish(result, trigger, severity=Severity.MEDIUM)
        elif self.publish_clean and result.get("available"):
            self._publish(result, trigger, severity=Severity.INFO)

        return result

    def _publish(self, result: dict, trigger: Optional[Event],
                 *, severity: Severity):
        rule_id = (
            "AMSI-MALWARE" if result.get("is_malware")
            else "AMSI-ADMIN-BLOCK" if result.get("is_blocked_admin")
            else "AMSI-CLEAN"
        )
        rule_name = (
            "AMSI provider flagged malware" if result.get("is_malware")
            else "AMSI admin policy block" if result.get("is_blocked_admin")
            else "AMSI scan clean"
        )
        # T1059 (Command and Scripting Interpreter) is the umbrella —
        # AMSI's primary value is interpreted-script visibility.
        self.bus.publish(Event(
            category=EventCategory.DETECTION_AMSI,
            severity=severity,
            source="amsi",
            mitre_attack="T1059",
            data={
                "rule_id": rule_id,
                "rule_name": rule_name,
                "filepath": result.get("path"),
                "sha256": result.get("sha256"),
                "size": result.get("size"),
                "amsi_result": result.get("result"),
                "is_malware": bool(result.get("is_malware")),
                "is_blocked_admin": bool(result.get("is_blocked_admin")),
                "trigger_event_id": trigger.event_id if trigger else None,
            },
        ))


# ── EICAR (industry-standard AV health probe) ──────────────────────
# Splitting the literal across two strings keeps THIS source file
# from getting flagged by string-matching AV during transfer; the
# pieces concatenate at import to the canonical EICAR test string.

_EICAR_HEAD = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
_EICAR_TAIL = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_TEST_STRING = _EICAR_HEAD + _EICAR_TAIL


__all__ = [
    "AmsiClient",
    "AmsiScanner",
    "EICAR_TEST_STRING",
    "AMSI_RESULT_DETECTED",
    "AMSI_RESULT_NOT_DETECTED",
]
