"""
AEGIS startup lockfile
========================
Atomic single-instance guard. Writes a PID file at startup and refuses to
start if another AEGIS process is already running and writing to the same
event store. Prevents the dual-writer split-brain that breaks the hash
chain when NSSM (or the operator) accidentally spawns a second instance
while the first hasn't fully terminated.

Logic:
  acquire_lock(path):
    1. If `path` exists and its PID is alive AND looks like AEGIS → refuse.
    2. Else (stale lock or no lock) → atomically create the file with
       O_CREAT|O_EXCL. If that race is lost, refuse.
  release_lock(path):
    Only unlinks if the file's recorded PID matches our own (so a stale-
    cleanup in another process can never delete a live lock).
"""

from __future__ import annotations

import os
import logging
from pathlib import Path

logger = logging.getLogger("aegis.utils.lockfile")


class LockHeld(RuntimeError):
    """Raised when another AEGIS instance already holds the lock."""


def _pid_looks_like_aegis(pid: int) -> bool:
    """True if `pid` is alive AND its command line / name suggests AEGIS.
    On any failure (no psutil, no perms, dead PID) returns False so the
    caller treats the lock as stale rather than blocking startup."""
    try:
        import psutil  # soft dependency
    except ImportError:
        # Without psutil we can't verify identity; conservative: assume stale
        # so we don't block forever on a leftover file from a crash.
        return False
    try:
        p = psutil.Process(pid)
        if not p.is_running():
            return False
        name = (p.name() or "").lower()
        cmd = " ".join(p.cmdline() or []).lower()
        # Be permissive — any python process whose cmdline mentions aegis,
        # or any process named aegis* (compiled binary in future).
        if "aegis" in cmd:
            return True
        if name.startswith("aegis"):
            return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False


def acquire_lock(path: str | os.PathLike) -> None:
    """Acquire the startup lock or raise LockHeld."""
    pid_path = Path(path)
    pid_path.parent.mkdir(parents=True, exist_ok=True)

    # Step 1 — if a lockfile exists, decide whether it's live or stale.
    if pid_path.exists():
        try:
            old_pid = int(pid_path.read_text().strip())
        except (ValueError, OSError):
            old_pid = 0
        if old_pid and _pid_looks_like_aegis(old_pid):
            raise LockHeld(
                f"AEGIS is already running (PID {old_pid}, lockfile {pid_path}). "
                f"Stop the existing instance before starting a new one."
            )
        # Stale — owner is dead or unrelated. Remove and continue.
        logger.info(f"Removing stale lockfile {pid_path} (old PID {old_pid})")
        try:
            pid_path.unlink()
        except OSError:
            pass

    # Step 2 — atomic exclusive create. Loses any race cleanly.
    try:
        fd = os.open(str(pid_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        try:
            other = pid_path.read_text().strip()
        except OSError:
            other = "?"
        raise LockHeld(
            f"AEGIS startup race lost — another instance acquired the lock "
            f"first (PID {other}, lockfile {pid_path})."
        )
    try:
        os.write(fd, str(os.getpid()).encode("ascii"))
    finally:
        os.close(fd)
    logger.info(f"Acquired startup lock {pid_path} (PID {os.getpid()})")


def release_lock(path: str | os.PathLike) -> None:
    """Release the lock IF it still belongs to us."""
    pid_path = Path(path)
    try:
        if not pid_path.exists():
            return
        try:
            content = pid_path.read_text().strip()
        except OSError:
            return
        if content == str(os.getpid()):
            pid_path.unlink()
            logger.info(f"Released startup lock {pid_path}")
    except OSError:
        pass


__all__ = ["acquire_lock", "release_lock", "LockHeld"]
