"""
AEGIS Response — Post-Action Hardening Re-Check
================================================
Step 5 of the quarantine-response cascade: after a case closes (kill +
quarantine + sweep + persistence hunt), re-baseline the host's hardening
posture and report what changed. The incident may have left behind a
SUID binary, a world-writable drop directory, a relaxed permission, or
a new SSH config tweak — declaring victory without re-scanning is how
defenders miss the second-stage payload.

What "post-action hardening re-check" means in commercial EDR
-------------------------------------------------------------
  Kaspersky System Watcher : "vulnerability re-scan" after rollback
  CrowdStrike              : posture drift events feeding the dashboard
  ESET                     : automatic re-audit after threat removal
  Microsoft Defender ASR   : continuous posture monitoring with delta alerts

Design contract
---------------
  * Baseline-driven. We persist the last accepted baseline as JSON keyed
    by (check_id, target). The diff is what's NEW since baseline, what
    was RESOLVED since baseline, and what's PERSISTENT.
  * No remediation. This module reports drift; auto-fixing would be a
    separate policy gate. (Auto-removing a hardening finding the user
    deliberately accepted is exactly how EDRs lose customer trust.)
  * Dependency-injectable runner. Tests inject a HardeningRunner with a
    controlled check set; production uses the real one.
  * Atomic baseline writes via temp + rename — a crash mid-write must
    not leave a half-baked baseline file that fails to parse.
  * Append-only event semantics. Each drift item is its own event row
    so the hash chain reflects the full story.
"""

import json
import logging
import tempfile
from pathlib import Path
from typing import Optional, Callable, Iterable

from aegis.hardening import HardeningRunner, Finding

logger = logging.getLogger("aegis.response.hardening_recheck")


def _finding_key(f: dict | Finding) -> str:
    """Stable identity for a finding: (check_id, target). Two findings
    with the same check_id but different targets are distinct drift items.
    """
    if isinstance(f, Finding):
        return f"{f.check_id}|{f.target}"
    return f"{f.get('check_id', '')}|{f.get('target', '')}"


def _to_dict(f: dict | Finding) -> dict:
    return f.to_dict() if isinstance(f, Finding) else dict(f)


def load_baseline(baseline_path: Path) -> dict[str, dict]:
    """Load the last-accepted baseline as {key: finding_dict}.
    Missing or unreadable baseline returns {} — caller treats every
    current finding as drift, which is the safe default for first run.
    """
    try:
        raw = json.loads(Path(baseline_path).read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    findings = raw.get("findings", []) if isinstance(raw, dict) else raw
    return {_finding_key(f): _to_dict(f) for f in findings}


def save_baseline(baseline_path: Path, findings: Iterable[dict | Finding]) -> None:
    """Persist a baseline atomically (temp file + rename)."""
    baseline_path = Path(baseline_path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "findings": [_to_dict(f) for f in findings],
    }
    fd, tmp = tempfile.mkstemp(prefix=".baseline_", dir=str(baseline_path.parent))
    try:
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        Path(tmp).replace(baseline_path)
    except Exception:
        try:
            Path(tmp).unlink()
        except OSError:
            pass
        raise


def diff_findings(
    baseline: dict[str, dict],
    current: list[dict | Finding],
) -> dict:
    """Classify current findings against a baseline.

    Returns:
        {
            "new":        [...],  # in current, not in baseline
            "resolved":   [...],  # in baseline, not in current
            "persistent": [...],  # in both
        }
    """
    current_map = {_finding_key(f): _to_dict(f) for f in current}
    new_keys = current_map.keys() - baseline.keys()
    resolved_keys = baseline.keys() - current_map.keys()
    persistent_keys = current_map.keys() & baseline.keys()
    return {
        "new": [current_map[k] for k in sorted(new_keys)],
        "resolved": [baseline[k] for k in sorted(resolved_keys)],
        "persistent": [current_map[k] for k in sorted(persistent_keys)],
    }


def run_recheck(
    baseline_path: Path | str,
    *,
    runner: Optional[HardeningRunner] = None,
    runner_factory: Optional[Callable[[], HardeningRunner]] = None,
    update_baseline: bool = True,
    platform: str = "auto",
) -> dict:
    """Execute the re-check: audit, diff against baseline, optionally
    write a new baseline.

    `runner` takes precedence over `runner_factory`; `runner_factory` is
    convenient for tests that want fresh runner state per call. If
    neither is provided, a default HardeningRunner(platform) is built.

    `update_baseline=False` is useful for "preview" calls that should
    NOT shift the baseline (e.g. a dashboard refresh).

    Returns a status dict with diff, total counts, baseline I/O state,
    and the path to the baseline file.
    """
    baseline_path = Path(baseline_path)
    if runner is None:
        runner = runner_factory() if runner_factory else HardeningRunner(platform)

    try:
        current = runner.audit()
    except Exception as e:
        logger.error(f"Hardening audit failed: {e}", exc_info=True)
        return {
            "status": "audit_failed",
            "error": str(e),
            "baseline_path": str(baseline_path),
        }

    baseline = load_baseline(baseline_path)
    baseline_existed = bool(baseline)
    diff = diff_findings(baseline, current)

    baseline_written = False
    baseline_error: Optional[str] = None
    if update_baseline:
        try:
            save_baseline(baseline_path, current)
            baseline_written = True
        except OSError as e:
            baseline_error = str(e)
            logger.warning(f"Baseline write failed: {e}")

    return {
        "status": "ok",
        "baseline_path": str(baseline_path),
        "baseline_existed": baseline_existed,
        "baseline_written": baseline_written,
        "baseline_error": baseline_error,
        "current_total": len(current),
        "baseline_total": len(baseline),
        "new_count": len(diff["new"]),
        "resolved_count": len(diff["resolved"]),
        "persistent_count": len(diff["persistent"]),
        "diff": diff,
    }
