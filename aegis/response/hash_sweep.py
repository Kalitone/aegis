"""
AEGIS Response — Hash Sweep (Sibling Hunt)
===========================================
Given the SHA-256 of a just-quarantined file, search a bounded set of
common drop zones for files with the identical hash and return the
matches. The caller (ResponseEngine) decides what to do with them —
typically: quarantine each with a parent_case_id link.

Why this exists
---------------
Droppers rarely write one file. A single malicious binary is routinely
staged in %TEMP%, %APPDATA%, ~/Downloads, and /dev/shm as copies. If
AEGIS only quarantines the detected instance, the rest remain.
Commercial EDRs (ESET "related objects", Kaspersky "threat group search")
all perform this sweep as a mandatory post-detection step.

Safety rails
------------
  * Drop zones are explicit — we do NOT walk the whole filesystem.
  * Size-match pre-filter: we don't SHA-256 a file whose size disagrees
    with the target. This is what makes the sweep cheap in practice.
  * Symlinks are skipped (prevents cycles + out-of-scope reads).
  * Mount boundaries are respected (no cross into /proc, /sys, netfs).
  * Wall-clock budget: sweep aborts when the budget is spent, returning
    whatever it found. An incomplete sweep is still useful.
  * Max file size cap: we skip hashing large files (unlikely to be an IOC
    carrier, and expensive to hash).
  * Excluded paths: caller supplies the quarantine_dir itself so we don't
    re-find our own freshly-quarantined evidence.
"""

import os
import time
import hashlib
import logging
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger("aegis.response.hash_sweep")


DEFAULT_TIME_BUDGET_S = 60.0
DEFAULT_MAX_FILE_MB = 200
DEFAULT_MAX_DEPTH = 10
_READ_CHUNK = 65536


def resolve_default_drop_zones() -> list[Path]:
    """Platform-appropriate list of directories a dropper commonly targets.

    We return only paths that exist on this host; unresolved env vars or
    missing directories are silently dropped. Order matters in theory
    (highest-signal first) but since the sweep runs until budget expires
    rather than short-circuiting, order is only cosmetic here.
    """
    candidates: list[str] = []

    if os.name == "nt":
        # Windows drop zones — environment-variable driven so each user's
        # profile is covered without hard-coding "bradl" etc.
        for var in ("TEMP", "TMP", "APPDATA", "LOCALAPPDATA",
                    "PROGRAMDATA", "USERPROFILE"):
            v = os.environ.get(var)
            if v:
                candidates.append(v)
        user = os.environ.get("USERPROFILE")
        if user:
            candidates.append(os.path.join(user, "Downloads"))
            candidates.append(os.path.join(user, "AppData", "Roaming"))
        candidates.extend(["C:\\Users\\Public", "C:\\Windows\\Temp"])
    else:
        # POSIX drop zones — tmp + XDG dirs + home + /dev/shm.
        candidates.extend(["/tmp", "/var/tmp", "/dev/shm"])
        home = os.environ.get("HOME")
        if home:
            candidates.extend([
                home,
                os.path.join(home, ".config"),
                os.path.join(home, ".local", "share"),
                os.path.join(home, "Downloads"),
            ])

    seen: set[str] = set()
    zones: list[Path] = []
    for c in candidates:
        p = Path(c).resolve() if c else None
        if not p or str(p) in seen:
            continue
        seen.add(str(p))
        try:
            if p.is_dir():
                zones.append(p)
        except OSError:
            continue
    return zones


def _hash_file(path: Path, max_bytes: int) -> Optional[str]:
    """SHA-256 a file. Returns None on any I/O failure or if oversized."""
    try:
        st = path.stat()
        if st.st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _is_excluded(path: Path, excluded_resolved: list[str]) -> bool:
    """True if `path` equals or lies under any excluded root."""
    try:
        s = str(path.resolve())
    except OSError:
        return True
    for root in excluded_resolved:
        if s == root or s.startswith(root + os.sep):
            return True
    return False


def sweep_for_siblings(
    target_hash: str,
    target_size: int,
    drop_zones: Iterable[Path],
    *,
    excluded_paths: Iterable[Path] = (),
    time_budget_s: float = DEFAULT_TIME_BUDGET_S,
    max_file_size_mb: int = DEFAULT_MAX_FILE_MB,
    max_depth: int = DEFAULT_MAX_DEPTH,
    follow_symlinks: bool = False,
) -> dict:
    """Walk drop zones, return paths whose SHA-256 matches `target_hash`.

    `target_size` is used as a cheap pre-filter: if a file's size doesn't
    match, we skip hashing. This is the primary mechanism that keeps the
    sweep from pegging a disk on a home directory full of media.

    Returns a dict:
        {
          "matches": [PosixPath, ...],
          "scanned": int,   # total files considered
          "hashed": int,    # number we actually SHA-256'd
          "skipped_large": int,
          "errors": int,
          "elapsed_s": float,
          "budget_exhausted": bool,
          "zones_walked": [str, ...]
        }
    """
    max_bytes = int(max_file_size_mb) * 1024 * 1024
    excluded = []
    for p in excluded_paths:
        try:
            excluded.append(str(Path(p).resolve()))
        except OSError:
            continue

    matches: list[Path] = []
    scanned = 0
    hashed = 0
    skipped_large = 0
    errors = 0
    zones_walked: list[str] = []
    start = time.monotonic()
    deadline = start + max(1.0, float(time_budget_s))
    budget_exhausted = False

    for zone in drop_zones:
        if time.monotonic() >= deadline:
            budget_exhausted = True
            break

        try:
            zone_resolved = zone.resolve()
        except OSError:
            errors += 1
            continue

        if _is_excluded(zone_resolved, excluded):
            continue

        zones_walked.append(str(zone_resolved))
        zone_depth = len(zone_resolved.parts)

        for dirpath, dirnames, filenames in os.walk(
            zone_resolved, followlinks=follow_symlinks
        ):
            if time.monotonic() >= deadline:
                budget_exhausted = True
                break

            # Don't cross mount boundaries — os.walk has no built-in
            # support, but we can check by comparing st_dev.
            try:
                zone_dev = zone_resolved.stat().st_dev
                cur_dev = os.stat(dirpath).st_dev
                if cur_dev != zone_dev:
                    dirnames[:] = []
                    continue
            except OSError:
                errors += 1
                dirnames[:] = []
                continue

            # Depth cap: prune deep subtrees.
            depth = len(Path(dirpath).parts) - zone_depth
            if depth >= max_depth:
                dirnames[:] = []

            # Prune excluded subdirs in-place so os.walk skips them.
            pruned: list[str] = []
            for d in dirnames:
                full = Path(dirpath) / d
                if _is_excluded(full, excluded):
                    continue
                # Skip symlinked dirs unless follow_symlinks explicitly on.
                if not follow_symlinks and full.is_symlink():
                    continue
                pruned.append(d)
            dirnames[:] = pruned

            for fname in filenames:
                if time.monotonic() >= deadline:
                    budget_exhausted = True
                    break

                full = Path(dirpath) / fname

                # Symlink files: skip unconditionally to avoid out-of-zone reads.
                try:
                    if full.is_symlink():
                        continue
                except OSError:
                    errors += 1
                    continue

                if _is_excluded(full, excluded):
                    continue

                scanned += 1
                try:
                    size = full.stat().st_size
                except OSError:
                    errors += 1
                    continue

                # Size pre-filter — the core cheap gate.
                if size != target_size:
                    continue
                if size > max_bytes:
                    skipped_large += 1
                    continue

                hashed += 1
                digest = _hash_file(full, max_bytes)
                if digest == target_hash:
                    matches.append(full)
                    logger.info(f"HASH-SWEEP match: {full}")

            if budget_exhausted:
                break

        if budget_exhausted:
            break

    elapsed = time.monotonic() - start
    return {
        "matches": matches,
        "scanned": scanned,
        "hashed": hashed,
        "skipped_large": skipped_large,
        "errors": errors,
        "elapsed_s": round(elapsed, 3),
        "budget_exhausted": budget_exhausted,
        "zones_walked": zones_walked,
    }
