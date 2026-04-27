"""
AEGIS Response — Purge Pipeline
================================
Quarantine state machine: STAGED → PURGED. Operator-confirmed removal
of quarantined evidence after a retention window. Until this step
landed, AEGIS never unlinked a quarantined file — the "quarantine" dir
grew forever and a chmod-000 file on disk is still a file on disk.

What "production purge" means in commercial EDR
-----------------------------------------------
  Kaspersky  : "Delete from quarantine" — two-stage retention policy
  ESET       : scheduled cleanup of quarantined items older than N days
  CrowdStrike: operator-driven "Release/Delete" with audit trail

Design contract
---------------
  * Evidence-first. If `require_forensic=True` and no matching forensic
    snapshot exists for the case, the purge is REFUSED. This prevents a
    misconfiguration from destroying the only record of an incident.
  * Append-only metadata. We DO NOT delete meta.json on purge — we
    mutate its `state` to PURGED + stamp `purged_at` + `purged_by`.
    The meta file is the audit trail; the binary is the evidence.
  * Secure overwrite before unlink. One zero-pass is honest: modern SSDs
    remap blocks and multi-pass shredding is theater. The goal is to
    prevent undelete/carving from recovering the sample.
  * Idempotent. Purging an already-PURGED case returns ALREADY_PURGED
    and does not re-overwrite anything.
  * No hash-chain implications. Purge publishes a new event (appended to
    the chain) — it never mutates prior event rows.
"""

import os
import json
import time
import logging
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger("aegis.response.purge")


_OVERWRITE_CHUNK = 1024 * 1024  # 1 MB zero-fill chunk
_DEFAULT_RETENTION_S = 30 * 86400  # 30 days


# ---------- Helpers ----------

def _find_case_meta(quarantine_dir: Path, case_id: str) -> Optional[Path]:
    """Locate the meta.json for a case. Filename embeds the case_id so a
    single glob is sufficient; we still verify the field on open to
    survive operator renames."""
    for candidate in quarantine_dir.glob(f"*_{case_id}_*.meta.json"):
        try:
            data = json.loads(candidate.read_text())
            if data.get("case_id") == case_id:
                return candidate
        except (OSError, json.JSONDecodeError):
            continue
    # Fallback: scan every meta in case the filename pattern is off.
    for candidate in quarantine_dir.glob("*.meta.json"):
        try:
            if json.loads(candidate.read_text()).get("case_id") == case_id:
                return candidate
        except (OSError, json.JSONDecodeError):
            continue
    return None


def _has_forensic_snapshot(forensics_dir: Optional[Path],
                           case_id: str) -> bool:
    """Evidence gate. We require at least one snapshot_*_<case_id>.json
    to exist. The filename convention is set by ResponseEngine._forensic_snapshot."""
    if not forensics_dir:
        return False
    try:
        return any(forensics_dir.glob(f"snapshot_*_{case_id}.json"))
    except OSError:
        return False


def _secure_overwrite(path: Path) -> int:
    """Zero-fill `path` in-place, fsync, and return bytes written.

    One zero pass + fsync. Multi-pass shredding (Gutmann, 7-pass, etc.)
    is obsolete for rotating disks and irrelevant for SSDs — the block
    you wrote to may not even be the block that held the old data.
    Best honest answer: zero what we can, unlink, move on.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return 0
    if size <= 0:
        return 0

    zeros = b"\x00" * min(_OVERWRITE_CHUNK, size)
    written = 0
    try:
        # We need write access, but the quarantined file is chmod 000.
        os.chmod(path, 0o600)
    except OSError as e:
        logger.debug(f"chmod before overwrite failed: {e}")

    try:
        with open(path, "r+b", buffering=0) as f:
            remaining = size
            while remaining > 0:
                chunk = zeros if remaining >= len(zeros) else b"\x00" * remaining
                f.write(chunk)
                written += len(chunk)
                remaining -= len(chunk)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
    except OSError as e:
        logger.warning(f"Secure overwrite incomplete for {path}: {e}")
    return written


# ---------- Public API ----------

def purge_case(
    case_id: str,
    quarantine_dir: Path | str,
    *,
    forensics_dir: Optional[Path | str] = None,
    require_forensic: bool = True,
    secure_overwrite: bool = True,
    operator: str = "system",
) -> dict:
    """Purge one quarantined file by case_id.

    Returns a status dict. Non-fatal misses (no such case, already
    purged, evidence missing) return status strings rather than raising
    so a caller iterating over many cases can carry on.

    Status values:
      - "purged"          : binary overwritten + unlinked, meta marked
      - "not_found"       : no meta for this case_id
      - "already_purged"  : case is already in PURGED state
      - "evidence_missing": require_forensic=True and no snapshot exists
      - "failed"          : I/O error; see `error` in returned dict
    """
    quarantine_dir = Path(quarantine_dir)
    forensics_dir = Path(forensics_dir) if forensics_dir else None

    meta_path = _find_case_meta(quarantine_dir, case_id)
    if meta_path is None:
        return {"status": "not_found", "case_id": case_id}

    try:
        meta = json.loads(meta_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {"status": "failed", "case_id": case_id, "error": str(e)}

    if meta.get("state") == "PURGED":
        return {
            "status": "already_purged",
            "case_id": case_id,
            "purged_at": meta.get("purged_at"),
            "meta_path": str(meta_path),
        }

    if require_forensic and not _has_forensic_snapshot(forensics_dir, case_id):
        return {
            "status": "evidence_missing",
            "case_id": case_id,
            "meta_path": str(meta_path),
            "message": (
                "Refusing to purge: no forensic snapshot for this case. "
                "Either capture one or pass require_forensic=False."
            ),
        }

    # Locate the binary. Its path is recorded in meta on quarantine; fall
    # back to pattern match in the quarantine dir if meta is missing it.
    q_path_str = meta.get("quarantine_path")
    q_path = Path(q_path_str) if q_path_str else None
    if q_path is None or not q_path.exists():
        # Re-derive from the meta filename convention: strip .meta.json.
        candidate = Path(str(meta_path).removesuffix(".meta.json"))
        q_path = candidate if candidate.exists() else None

    bytes_overwritten = 0
    binary_unlinked = False
    if q_path and q_path.exists():
        if secure_overwrite:
            bytes_overwritten = _secure_overwrite(q_path)
        try:
            os.chmod(q_path, 0o600)
        except OSError:
            pass
        try:
            q_path.unlink()
            binary_unlinked = True
        except OSError as e:
            return {
                "status": "failed",
                "case_id": case_id,
                "error": f"unlink failed: {e}",
                "bytes_overwritten": bytes_overwritten,
            }
    # If the binary was already missing, we still mark the case PURGED —
    # the file is gone either way, and the meta.json needs to reflect
    # reality so idempotent re-purge doesn't spin.

    purged_at = time.time()
    meta["state"] = "PURGED"
    meta["purged_at"] = purged_at
    meta["purged_by"] = operator
    meta["purge_bytes_overwritten"] = bytes_overwritten
    meta["purge_secure_overwrite"] = bool(secure_overwrite)

    try:
        meta_path.write_text(json.dumps(meta, indent=2, default=str))
    except OSError as e:
        return {
            "status": "failed",
            "case_id": case_id,
            "error": f"meta update failed: {e}",
            "bytes_overwritten": bytes_overwritten,
            "binary_unlinked": binary_unlinked,
        }

    logger.warning(f"PURGED [case={case_id}]: binary unlinked "
                   f"({bytes_overwritten} bytes overwritten)")

    return {
        "status": "purged",
        "case_id": case_id,
        "meta_path": str(meta_path),
        "quarantine_path": str(q_path) if q_path else None,
        "bytes_overwritten": bytes_overwritten,
        "binary_unlinked": binary_unlinked,
        "purged_at": purged_at,
        "purged_by": operator,
        "original_path": meta.get("original_path"),
        "sha256": meta.get("sha256"),
    }


def list_eligible(
    quarantine_dir: Path | str,
    *,
    retention_s: float = _DEFAULT_RETENTION_S,
    now: Optional[float] = None,
) -> list[dict]:
    """Return STAGED case metas older than retention. Safe to call often
    — pure enumeration, no side effects."""
    quarantine_dir = Path(quarantine_dir)
    now = now if now is not None else time.time()
    cutoff = now - retention_s
    eligible: list[dict] = []
    for meta_path in quarantine_dir.glob("*.meta.json"):
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if meta.get("state") != "STAGED":
            continue
        q_at = meta.get("quarantined_at")
        if not q_at or q_at > cutoff:
            continue
        eligible.append({
            "case_id": meta.get("case_id"),
            "meta_path": str(meta_path),
            "quarantined_at": q_at,
            "age_s": now - q_at,
        })
    return eligible


def purge_expired(
    quarantine_dir: Path | str,
    *,
    retention_s: float = _DEFAULT_RETENTION_S,
    forensics_dir: Optional[Path | str] = None,
    require_forensic: bool = True,
    secure_overwrite: bool = True,
    operator: str = "scheduled",
    now: Optional[float] = None,
) -> list[dict]:
    """Bulk purge: every STAGED case older than retention. Returns the
    per-case status dicts. One failure does not stop the batch."""
    eligible = list_eligible(quarantine_dir, retention_s=retention_s, now=now)
    results: list[dict] = []
    for e in eligible:
        case_id = e.get("case_id")
        if not case_id:
            continue
        results.append(purge_case(
            case_id, quarantine_dir,
            forensics_dir=forensics_dir,
            require_forensic=require_forensic,
            secure_overwrite=secure_overwrite,
            operator=operator,
        ))
    return results


# ---------- Forensics rotation ----------

def _parse_case_id_from_snapshot(path: Path) -> Optional[str]:
    """Extract case_id from a snapshot filename of the form
    `snapshot_<epoch>_<case_id>.json`. Returns None if the convention
    doesn't fit; the caller can then fall back to reading the JSON."""
    stem = path.stem  # snapshot_<epoch>_<case_id>
    if not stem.startswith("snapshot_"):
        return None
    parts = stem.split("_", 2)
    # ["snapshot", "<epoch>", "<case_id>"]
    if len(parts) != 3 or not parts[2]:
        return None
    return parts[2]


def _case_ids_from_quarantine(quarantine_dir: Path) -> set[str]:
    """Every case_id referenced by a *.meta.json in the quarantine dir.
    Used as the protection set for forensics rotation — we never delete
    a snapshot whose case still has a meta on disk, since `purge_case`
    relies on snapshot existence as its evidence gate."""
    case_ids: set[str] = set()
    try:
        meta_paths = list(quarantine_dir.glob("*.meta.json"))
    except OSError:
        return case_ids
    for meta_path in meta_paths:
        try:
            data = json.loads(meta_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        cid = data.get("case_id")
        if cid:
            case_ids.add(cid)
    return case_ids


def purge_forensics(
    forensics_dir: Path | str,
    retention_s: int,
    now: float,
    *,
    protected_case_ids: Iterable[str] = (),
) -> dict:
    """Delete forensic snapshots older than retention.

    Walks `forensics_dir/snapshot_*.json` only — anything else in the
    directory (baselines, hand-written notes, sub-dirs) is left alone.
    A snapshot is kept if it is newer than the cutoff OR if its case_id
    is in `protected_case_ids` (typically every case currently on disk
    in quarantine, so quarantine's evidence gate is never undermined).

    Deletion is non-secure unlink. These files snapshot public process
    state and have already been replicated into quarantine meta when
    they mattered for evidence.
    """
    forensics_dir = Path(forensics_dir)
    protected = set(protected_case_ids)
    cutoff = now - retention_s

    scanned = 0
    purged = 0
    skipped_recent = 0
    skipped_protected = 0
    errors: list[str] = []

    try:
        candidates = list(forensics_dir.glob("snapshot_*.json"))
    except OSError as e:
        return {
            "scanned": 0, "purged": 0,
            "skipped_recent": 0, "skipped_protected": 0,
            "errors": [f"glob failed: {e}"],
        }

    for path in candidates:
        scanned += 1
        try:
            mtime = path.stat().st_mtime
        except OSError as e:
            errors.append(f"{path.name}: stat failed: {e}")
            continue

        if mtime > cutoff:
            skipped_recent += 1
            continue

        case_id = _parse_case_id_from_snapshot(path)
        if case_id is None:
            # Filename doesn't fit the convention — fall back to JSON.
            try:
                data = json.loads(path.read_text())
                case_id = (data.get("trigger_event", {})
                               .get("data", {})
                               .get("case_id"))
            except (OSError, json.JSONDecodeError) as e:
                errors.append(f"{path.name}: malformed json: {e}")
                continue

        if case_id and case_id in protected:
            skipped_protected += 1
            continue

        try:
            path.unlink()
            purged += 1
        except OSError as e:
            errors.append(f"{path.name}: unlink failed: {e}")

    return {
        "scanned": scanned,
        "purged": purged,
        "skipped_recent": skipped_recent,
        "skipped_protected": skipped_protected,
        "errors": errors,
    }


def purge_expired_all(
    quarantine_dir: Path | str,
    *,
    retention_s: float = _DEFAULT_RETENTION_S,
    forensics_dir: Optional[Path | str] = None,
    forensics_retention_s: int = 0,
    require_forensic: bool = True,
    secure_overwrite: bool = True,
    operator: str = "scheduled",
    now: Optional[float] = None,
) -> dict:
    """Combined rotation: quarantine + forensics.

    Always runs the quarantine purge. Also rotates forensic snapshots
    when `forensics_dir` is provided AND `forensics_retention_s > 0`.
    Returns `{"quarantine": [...], "forensics": {...}}` in that case;
    otherwise returns `{"quarantine": [...]}` to keep callers that only
    care about quarantine results unsurprised.
    """
    q_results = purge_expired(
        quarantine_dir,
        retention_s=retention_s,
        forensics_dir=forensics_dir,
        require_forensic=require_forensic,
        secure_overwrite=secure_overwrite,
        operator=operator,
        now=now,
    )
    out: dict = {"quarantine": q_results}

    if forensics_dir and forensics_retention_s > 0:
        protected = _case_ids_from_quarantine(Path(quarantine_dir))
        out["forensics"] = purge_forensics(
            forensics_dir,
            retention_s=int(forensics_retention_s),
            now=now if now is not None else time.time(),
            protected_case_ids=protected,
        )
    return out
