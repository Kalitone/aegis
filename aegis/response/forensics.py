"""
AEGIS Response — Forensic Attribution
======================================
Capture the execution chain for a detection AT THE MOMENT OF DETECTION,
before kill/quarantine destroy the evidence. The snapshot this module
produces is the forensic spine of every downstream response action:
kill, quarantine, persistence hunt, and purge all reference the same
case context so attribution survives process death.

Design choices:
  - One capture, reused by every action. Kill runs before quarantine in the
    default severity→actions map; walking parents() post-kill returns nothing.
  - Tolerant of dead/denied processes: missing ancestors are recorded,
    never aborted. A partial attribution is still useful forensic data.
  - Bounded: ancestor walk capped, module list capped, exe hashing size-capped
    so a 4 GB binary doesn't stall the responder.

Parallels in commercial EDR:
  - CrowdStrike Falcon: "process tree"
  - ESET Inspect: "execution chain"
  - Kaspersky EDR Expert: "activity trace"
"""

import os
import time
import hashlib
import logging
from typing import Optional

import psutil

logger = logging.getLogger("aegis.response.forensics")


# Environment variables kept in the snapshot. Security-relevant:
#   LD_PRELOAD / LD_AUDIT / DYLD_* → library injection (T1574.006)
#   PYTHONPATH / PYTHONSTARTUP     → import-hook persistence
#   PATH                            → trojanized binary placement
# Everything else is dropped to avoid leaking secrets.
_ENV_KEEP = {
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
    "PATH", "PYTHONPATH", "PYTHONSTARTUP",
    "HOME", "USER", "USERNAME",
    "SystemRoot", "PROCESSOR_ARCHITECTURE", "COMSPEC",
}

_MAX_ANCESTORS = 16
_MAX_OPEN_FILES = 50
_MAX_CONNECTIONS = 50
_MAX_MODULES = 200
_HASH_SIZE_CAP = 64 * 1024 * 1024  # Skip hashing binaries larger than this.


def _hash_exe(path: str) -> Optional[str]:
    """SHA-256 an executable; None on any failure (including size cap)."""
    try:
        size = os.path.getsize(path)
        if size > _HASH_SIZE_CAP:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _safe_call(fn, default=None):
    """Invoke a psutil attribute getter, returning default on Access/NoSuch."""
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError,
            NotImplementedError):
        return default


def _proc_snapshot(proc: psutil.Process, include_heavy: bool = False) -> dict:
    """Snapshot one process. heavy=True adds modules/open_files/connections.

    The triggering process gets heavy; ancestors don't — the cost scales
    with depth and the signal diminishes beyond the immediate launcher.
    """
    snap: dict = {"pid": proc.pid}
    with proc.oneshot():
        snap["ppid"] = _safe_call(proc.ppid)
        snap["name"] = _safe_call(proc.name)
        snap["exe"] = _safe_call(proc.exe)
        snap["cwd"] = _safe_call(proc.cwd)
        snap["username"] = _safe_call(proc.username)
        snap["create_time"] = _safe_call(proc.create_time)
        snap["status"] = _safe_call(proc.status)
        cmd = _safe_call(proc.cmdline, default=[]) or []
        snap["cmdline"] = " ".join(cmd)
        env = _safe_call(proc.environ, default={}) or {}
        snap["environ"] = {k: v for k, v in env.items() if k in _ENV_KEEP}

    if snap.get("exe"):
        snap["exe_sha256"] = _hash_exe(snap["exe"])

    if include_heavy:
        files = _safe_call(proc.open_files, default=[]) or []
        snap["open_files"] = [f.path for f in files][:_MAX_OPEN_FILES]

        conns = _safe_call(lambda: proc.connections(kind="inet"),
                           default=[]) or []
        snap["connections"] = [
            {
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
            }
            for c in conns
        ][:_MAX_CONNECTIONS]

        # memory_maps catches DLL sideload / LD_PRELOAD / reflective loads.
        maps = _safe_call(lambda: proc.memory_maps(grouped=True),
                          default=[]) or []
        snap["loaded_modules"] = [m.path for m in maps][:_MAX_MODULES]

    return snap


def capture_execution_chain(pid: int) -> dict:
    """Capture the triggering process + full ancestry back toward init.

    Call this BEFORE any destructive response action. The returned dict
    is JSON-serializable and embeds into quarantine meta.json and the
    response.quarantine event payload so attribution is preserved even
    after kill/quarantine succeed.
    """
    result: dict = {
        "captured_at": time.time(),
        "triggering_pid": pid,
        "triggering_process": None,
        "ancestors": [],
        "attribution_complete": False,
        "notes": [],
    }

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        result["notes"].append(f"pid {pid} already exited before capture")
        return result
    except Exception as e:
        result["notes"].append(f"could not open pid {pid}: {e}")
        return result

    try:
        result["triggering_process"] = _proc_snapshot(proc, include_heavy=True)
    except Exception as e:
        logger.debug(f"triggering snapshot partial failure: {e}")
        result["notes"].append(f"triggering snapshot error: {e}")

    try:
        parents = proc.parents()
    except Exception as e:
        result["notes"].append(f"parent walk failed: {e}")
        parents = []

    for ancestor in parents[:_MAX_ANCESTORS]:
        try:
            result["ancestors"].append(_proc_snapshot(ancestor, include_heavy=False))
        except psutil.NoSuchProcess:
            result["ancestors"].append({"pid": ancestor.pid, "gone": True})
        except Exception as e:
            result["ancestors"].append({"pid": ancestor.pid, "error": str(e)})

    result["attribution_complete"] = bool(
        result["triggering_process"] and parents
    )
    return result
