"""
AEGIS Response Engine
=======================
Automated response to detection events.
Maps severity → action: kill, quarantine, forensic snapshot, alert.

Safety: All destructive actions are logged before execution.
Forensic data is captured BEFORE any kill/quarantine action.
"""

import os
import time
import uuid
import json
import shutil
import signal
import logging
import hashlib
import platform
from pathlib import Path
from typing import Optional

import psutil

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.response.forensics import capture_execution_chain
from aegis.response.hash_sweep import (
    sweep_for_siblings,
    resolve_default_drop_zones,
    DEFAULT_TIME_BUDGET_S,
    DEFAULT_MAX_FILE_MB,
    DEFAULT_MAX_DEPTH,
)
from aegis.response.persistence import (
    hunt_persistence,
    build_indicators_from_quarantine,
)
from aegis.response.purge import (
    purge_case as _purge_case,
    purge_expired_all as _purge_expired_all,
    list_eligible as _list_eligible,
)
from aegis.response.hardening_recheck import run_recheck as _run_hardening_recheck

logger = logging.getLogger("aegis.response")


# ── Quarantine allow-list ────────────────────────────────────────────
# Canonical paths we refuse to quarantine even on a "high" detection.
# A historical FP on Microsoft OneAuth (`credential_harvester` rule
# matched the live MSA token store) proved that breaking SSO / browser
# profiles / mailboxes is a self-inflicted DoS no rule earns. Substrings
# are matched case-insensitively against the normalised (backslash-form)
# path; entries starting with `/` are matched against the original
# forward-slash form so Linux paths work too.
_DEFAULT_QUARANTINE_ALLOW_SUBSTRINGS: tuple[str, ...] = (
    # Windows credential / SSO stores
    "\\microsoft\\oneauth\\",
    "\\microsoft\\tokenbroker\\",
    "\\microsoft\\credentials\\",
    "\\microsoft\\vault\\",
    "\\microsoft\\windows\\notifications\\",
    # Browser profiles
    "\\microsoft\\edge\\user data\\",
    "\\google\\chrome\\user data\\",
    "\\mozilla\\firefox\\profiles\\",
    # Mail + cloud sync
    "\\onedrive\\",
    "\\outlook files\\",
    # Linux equivalents
    "/.config/google-chrome/",
    "/.config/microsoft-edge/",
    "/.mozilla/firefox/",
    "/.local/share/keyrings/",
    "/.ssh/",
    "/.gnupg/",
    # macOS
    "/library/keychains/",
)

# File extensions whose entire bodies are routinely string-matched into
# false positives (Outlook personal stores, multi-GB and irreplaceable).
_DEFAULT_QUARANTINE_ALLOW_EXTENSIONS: tuple[str, ...] = (
    ".ost",
    ".pst",
)


def _is_quarantine_allowed(
    file_path: str,
    *,
    extra_substrings: tuple[str, ...] = (),
) -> Optional[str]:
    """Return the matching allow-list rule, or None.

    Used as a hard pre-flight gate inside `_quarantine_path()`. Built-in
    canonical paths and operator-supplied extras are normalised the same
    way (case-folded, both slash forms) so the substring check survives
    drive-letter and casing variation.
    """
    if not file_path:
        return None
    posix = file_path.lower()
    norm = posix.replace("/", "\\")

    for substring in _DEFAULT_QUARANTINE_ALLOW_SUBSTRINGS:
        if substring.startswith("/"):
            if substring in posix:
                return f"default:{substring}"
        elif substring in norm:
            return f"default:{substring}"

    for ext in _DEFAULT_QUARANTINE_ALLOW_EXTENSIONS:
        if norm.endswith(ext):
            return f"default-ext:{ext}"

    for substring in extra_substrings:
        s = substring.lower()
        if s.startswith("/"):
            if s in posix:
                return f"config:{substring}"
        else:
            n = s.replace("/", "\\")
            if n in norm:
                return f"config:{substring}"

    return None


def _hash_file_chunked(filepath: str) -> str:
    """SHA-256 hash a file in 64 KB chunks (avoids reading entire file into memory)."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _lock_quarantined_file(filepath: str):
    """Lock a quarantined file to prevent accidental execution."""
    if platform.system().lower() == "windows":
        try:
            import subprocess
            # Remove all permissions except SYSTEM (prevents user from running it)
            subprocess.run(
                ["icacls", str(filepath), "/inheritance:r",
                 "/grant:r", "SYSTEM:(R)", "/grant:r", "Administrators:(R)"],
                capture_output=True, timeout=10,
            )
        except Exception:
            pass
    try:
        os.chmod(str(filepath), 0o000)
    except OSError:
        pass


class ResponseEngine:
    """Automated incident response engine."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self.auto_respond = config.get("auto_respond", True)
        # Per-source overrides — e.g. anomaly detector publishes from
        # source="anomaly" and the audit recommended NOT auto-quarantining
        # on Isolation Forest alone (high FP tail). Map source name → bool;
        # missing sources fall back to the global `auto_respond` flag.
        self._auto_respond_per_source: dict[str, bool] = {
            str(k): bool(v)
            for k, v in (config.get("auto_respond_sources") or {}).items()
        }
        self.quarantine_dir = Path(config.get("quarantine_dir", "quarantine"))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.forensics_dir = Path(config.get("forensics_dir", "data/forensics"))
        self.forensics_dir.mkdir(parents=True, exist_ok=True)
        self._running = False
        self._action_count = 0

        # Severity → actions mapping
        self.severity_actions = config.get("severity_actions", {
            "critical": ["kill_process", "quarantine_file", "forensic_snapshot", "alert"],
            "high": ["quarantine_file", "alert", "forensic_snapshot"],
            "medium": ["alert", "log"],
            "low": ["log"],
        })

        # Protected PIDs (never kill our own process tree)
        self._protected_pids = {os.getpid(), 1}
        try:
            self._protected_pids.add(os.getppid())
        except OSError:
            pass

        # Hash-sweep config: find sibling IOCs in common drop zones after a
        # primary quarantine. Enabled by default because a single quarantine
        # without scope expansion is the #1 reason malware "comes back".
        sweep_cfg = config.get("hash_sweep", {}) or {}
        self.hash_sweep_enabled = bool(sweep_cfg.get("enabled", True))
        self.hash_sweep_time_budget_s = float(
            sweep_cfg.get("time_budget_s", DEFAULT_TIME_BUDGET_S)
        )
        self.hash_sweep_max_file_mb = int(
            sweep_cfg.get("max_file_size_mb", DEFAULT_MAX_FILE_MB)
        )
        self.hash_sweep_max_depth = int(
            sweep_cfg.get("max_depth", DEFAULT_MAX_DEPTH)
        )
        # Caller can override drop zones (tests, hardened hosts). If not
        # specified, resolve platform defaults lazily on first sweep so
        # env changes between __init__ and first event are respected.
        self._hash_sweep_zones_override: Optional[list[Path]] = None
        if zones := sweep_cfg.get("drop_zones"):
            self._hash_sweep_zones_override = [Path(z) for z in zones]
        # Paths never scanned — the quarantine dir must be excluded or we'd
        # "find" our own freshly quarantined file. Callers can add more.
        self._hash_sweep_excluded: list[Path] = [self.quarantine_dir]
        if extra := sweep_cfg.get("excluded_paths"):
            self._hash_sweep_excluded.extend(Path(p) for p in extra)

        # Persistence-hunt config: after a quarantine (+ sweep), scan OS
        # persistence surfaces for references to the quarantined file.
        # Report-only by default — auto-remove is a separate policy gate.
        persist_cfg = config.get("persistence_hunt", {}) or {}
        self.persistence_hunt_enabled = bool(persist_cfg.get("enabled", True))
        self._persistence_roots: Optional[dict] = persist_cfg.get("roots")
        self._persistence_platform: Optional[str] = persist_cfg.get("platform")

        # Quarantine allow-list: canonical paths the engine will refuse to
        # quarantine even on a high-severity detection. Operators can extend
        # the built-in list via `response.quarantine.allow_list_paths`.
        quarantine_cfg = config.get("quarantine", {}) or {}
        self._quarantine_allow_extra: tuple[str, ...] = tuple(
            quarantine_cfg.get("allow_list_paths", []) or []
        )

        # Purge-pipeline config: actual deletion of quarantined evidence
        # after a retention window. `require_forensic` is the evidence
        # gate — default true so a misconfig can't destroy the only
        # record of an incident.
        purge_cfg = config.get("purge", {}) or {}
        self.purge_retention_s = float(
            purge_cfg.get("retention_days", 30) * 86400
        )
        self.purge_require_forensic = bool(
            purge_cfg.get("require_forensic", True)
        )
        self.purge_secure_overwrite = bool(
            purge_cfg.get("secure_overwrite", True)
        )

        # Forensics rotation: snapshot files accumulate at ~340 MB/day
        # (audit found 11k snapshots / 2.2 GB in 6.5 days). Default
        # 30-day retention; case_ids still in quarantine are protected
        # so the purge evidence-gate is never undermined.
        forensics_cfg = config.get("forensics", {}) or {}
        self.forensics_retention_s = int(
            forensics_cfg.get("retention_days", 30) * 86400
        )

        # Hardening re-check config: after a case closes, re-baseline the
        # host's hardening posture and emit one drift event per new
        # finding. The injected runner override is for tests; production
        # builds a default HardeningRunner per re-check.
        recheck_cfg = config.get("hardening_recheck", {}) or {}
        self.hardening_recheck_enabled = bool(recheck_cfg.get("enabled", True))
        default_baseline = self.forensics_dir / "hardening_baseline.json"
        self.hardening_baseline_path = Path(
            recheck_cfg.get("baseline_path", default_baseline)
        )
        self.hardening_recheck_platform = recheck_cfg.get("platform", "auto")
        # Test/DI hook: caller can pass either a runner instance or a
        # zero-arg factory. Factory wins for fresh state per call.
        self._hardening_runner = recheck_cfg.get("runner")
        self._hardening_runner_factory = recheck_cfg.get("runner_factory")

    def start(self):
        """Subscribe to all detection events."""
        self.bus.subscribe("detection.*", self._on_detection)
        self._running = True
        logger.info(f"Response engine started. Auto-respond: {self.auto_respond}")

    def stop(self):
        self._running = False
        logger.info(f"Response engine stopped. Actions taken: {self._action_count}")

    # ---------- Purge API (operator + scheduler facing) ----------

    def purge_case(self, case_id: str, *,
                   operator: str = "operator",
                   require_forensic: Optional[bool] = None,
                   secure_overwrite: Optional[bool] = None) -> dict:
        """Operator-triggered purge of one quarantined case.

        Publishes a response.purge event reflecting the outcome. Evidence
        gate and secure-overwrite policy default to the engine config
        but can be overridden per-call (useful for a "force" UI action).
        """
        result = _purge_case(
            case_id, self.quarantine_dir,
            forensics_dir=self.forensics_dir,
            require_forensic=(self.purge_require_forensic
                              if require_forensic is None else require_forensic),
            secure_overwrite=(self.purge_secure_overwrite
                              if secure_overwrite is None else secure_overwrite),
            operator=operator,
        )
        severity = Severity.HIGH if result["status"] == "purged" else Severity.INFO
        self.bus.publish(Event(
            category=EventCategory.RESPONSE_PURGE,
            severity=severity,
            source="response",
            data={"action": "purge_case", **result},
        ))
        return result

    def purge_expired(self, *, operator: str = "scheduled") -> dict:
        """Bulk purge every STAGED case older than the retention window.

        Publishes one summary response.purge event plus individual
        per-case events so the audit trail captures each outcome. Also
        rotates forensic snapshots when `forensics_retention_s` is set;
        snapshot case_ids still referenced by quarantine metas are
        protected so the evidence gate never breaks.
        """
        combined = _purge_expired_all(
            self.quarantine_dir,
            retention_s=self.purge_retention_s,
            forensics_dir=self.forensics_dir,
            forensics_retention_s=self.forensics_retention_s,
            require_forensic=self.purge_require_forensic,
            secure_overwrite=self.purge_secure_overwrite,
            operator=operator,
        )
        results = combined["quarantine"]
        for r in results:
            self.bus.publish(Event(
                category=EventCategory.RESPONSE_PURGE,
                severity=Severity.HIGH if r["status"] == "purged" else Severity.INFO,
                source="response",
                data={"action": "purge_case", **r},
            ))
        summary = {
            "action": "purge_expired_summary",
            "total": len(results),
            "purged": sum(1 for r in results if r["status"] == "purged"),
            "evidence_missing": sum(1 for r in results
                                    if r["status"] == "evidence_missing"),
            "already_purged": sum(1 for r in results
                                  if r["status"] == "already_purged"),
            "failed": sum(1 for r in results if r["status"] == "failed"),
            "retention_s": self.purge_retention_s,
            "operator": operator,
        }
        forensics_summary = combined.get("forensics")
        if forensics_summary is not None:
            summary["forensics"] = forensics_summary
            self.bus.publish(Event(
                category=EventCategory.RESPONSE_PURGE,
                severity=Severity.INFO,
                source="response",
                data={
                    "action": "forensics_rotated",
                    "operator": operator,
                    "retention_s": self.forensics_retention_s,
                    **forensics_summary,
                },
            ))
        self.bus.publish(Event(
            category=EventCategory.RESPONSE_PURGE,
            severity=Severity.INFO,
            source="response",
            data=summary,
        ))
        return {"summary": summary, "results": results,
                "forensics": forensics_summary}

    def list_purge_eligible(self) -> list[dict]:
        """Inspector — what WOULD `purge_expired()` act on right now?"""
        return _list_eligible(
            self.quarantine_dir, retention_s=self.purge_retention_s,
        )

    def _on_detection(self, event: Event):
        """Handle a detection event — determine and execute response."""
        severity = event.severity.value
        actions = self.severity_actions.get(severity, ["log"])

        logger.info(f"RESPONSE: Severity={severity} Rule={event.data.get('rule_id', 'N/A')} "
                     f"Actions={actions}")

        # Build the case context BEFORE any destructive action. Kill runs
        # before quarantine in the default action list, so walking the
        # process tree post-kill returns nothing. Capture once, reuse across
        # every action so attribution is consistent after the source dies.
        case = self._build_case_context(event)

        # Per-source override wins over the global flag — see __init__.
        source_override = self._auto_respond_per_source.get(event.source)
        effective_auto = (
            self.auto_respond if source_override is None else source_override
        )
        if not effective_auto:
            self.bus.publish(Event(
                category=EventCategory.RESPONSE_ALERT,
                severity=event.severity,
                source="response",
                data={
                    "original_event": event.to_dict(),
                    "suggested_actions": actions,
                    "case": case,
                    "auto_respond": False,
                    "message": "Auto-respond disabled. Manual action required.",
                },
            ))
            return

        for action in actions:
            try:
                if action == "kill_process":
                    self._kill_process(event, case)
                elif action == "quarantine_file":
                    self._quarantine_file(event, case)
                elif action == "forensic_snapshot":
                    self._forensic_snapshot(event, case)
                elif action == "alert":
                    self._alert(event, case)
                elif action == "log":
                    self._log_detection(event)
                self._action_count += 1
            except Exception as e:
                logger.error(f"Response action '{action}' failed: {e}", exc_info=True)

    def _build_case_context(self, event: Event) -> dict:
        """Capture immutable forensic attribution for this detection.

        Generates a case_id, snapshots the triggering process and its
        ancestry, and returns a dict that downstream actions fold into
        their metadata. Never raises — a failed capture still produces
        a marker so the case file isn't silently empty.
        """
        pid = (event.data.get("pid")
               or event.data.get("source_event", {}).get("pid"))
        case: dict = {
            "case_id": uuid.uuid4().hex[:12],
            "detection_event_id": event.event_id,
            "detection_category": event.category.value,
            "rule_id": event.data.get("rule_id", ""),
            "rule_name": event.data.get("rule_name",
                                        event.data.get("rule", "")),
            "mitre_attack": event.mitre_attack,
            "severity": event.severity.value,
            "execution_chain": None,
        }
        if pid:
            try:
                case["execution_chain"] = capture_execution_chain(int(pid))
            except Exception as e:
                logger.error(f"Execution chain capture failed: {e}",
                             exc_info=True)
                case["execution_chain"] = {
                    "error": str(e),
                    "triggering_pid": pid,
                    "attribution_complete": False,
                }
        return case

    def _kill_process(self, event: Event, case: dict):
        """Kill a malicious process and its children."""
        pid = event.data.get("pid") or event.data.get("source_event", {}).get("pid")
        if not pid:
            logger.warning("Kill requested but no PID available")
            return

        if pid in self._protected_pids:
            logger.warning(f"Refusing to kill protected PID {pid}")
            return

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            cmdline = " ".join(proc.cmdline() or [])

            # Capture state before kill
            proc_info = {
                "pid": pid,
                "name": name,
                "cmdline": cmdline,
                "status": proc.status(),
                "username": proc.username(),
                "create_time": proc.create_time(),
            }

            # Kill children first, then parent
            children = proc.children(recursive=True)
            for child in children:
                if child.pid not in self._protected_pids:
                    try:
                        child.kill()
                        logger.info(f"Killed child process: PID={child.pid}")
                    except psutil.NoSuchProcess:
                        pass

            proc.kill()
            logger.warning(f"KILLED: PID={pid} ({name}) CMD='{cmdline[:100]}'")

            self.bus.publish(Event(
                category=EventCategory.RESPONSE_KILL,
                severity=Severity.HIGH,
                source="response",
                data={
                    "action": "process_killed",
                    "process_info": proc_info,
                    "children_killed": [c.pid for c in children],
                    "reason": event.data.get("rule_name", "detection"),
                    "case": case,
                },
            ))

        except psutil.NoSuchProcess:
            logger.info(f"Process {pid} already exited")
        except psutil.AccessDenied:
            logger.error(f"Access denied killing PID {pid}")
        except Exception as e:
            logger.error(f"Failed to kill PID {pid}: {e}")

    def _quarantine_file(self, event: Event, case: dict):
        """Detection-driven quarantine: move the detected file, then sweep
        drop zones for identical-hash siblings and quarantine those too."""
        filepath = (event.data.get("filepath") or
                    event.data.get("path") or
                    event.data.get("source_event", {}).get("path"))

        if not filepath or not os.path.exists(filepath):
            return

        primary = self._quarantine_path(
            filepath, case,
            reason=event.data.get("rule_name", "detection"),
            rule_id=event.data.get("rule_id", ""),
        )
        if not primary:
            return

        # Scope expansion: hash-sweep for siblings in common drop zones.
        # Siblings go through _quarantine_path with parent_case_id set so
        # they do NOT re-trigger another sweep (prevents recursion).
        siblings: list[dict] = []
        if self.hash_sweep_enabled:
            siblings = self._run_hash_sweep(primary, case) or []

        # Root-cause hunt: with the file contained, find persistence
        # mechanisms that would respawn it. Detection only — remediation
        # is gated on operator policy.
        if self.persistence_hunt_enabled:
            self._run_persistence_hunt(primary, siblings)

        # Post-action re-baseline: did the incident leave hardening drift
        # behind (new SUID, world-writable dir, ...)? Diff against the last
        # baseline, publish per-delta drift events, refresh baseline.
        if self.hardening_recheck_enabled:
            self._run_hardening_recheck(primary)

    def _quarantine_path(
        self,
        filepath: str,
        case: dict,
        *,
        reason: str = "sibling of detection",
        rule_id: str = "",
        parent_case_id: Optional[str] = None,
    ) -> Optional[dict]:
        """Move one file to quarantine and write its meta.json.

        Used for both the primary detection quarantine AND sibling
        quarantines from the hash sweep. `parent_case_id`, when set,
        marks this quarantine as a sibling so the caller's sweep loop
        knows not to recurse.

        Returns a dict with the primary keys (case_id, sha256, size,
        quarantine_path, meta_path) on success, or None on failure.
        """
        if not filepath or not os.path.exists(filepath):
            return None

        # Allow-list pre-flight: refuse to quarantine canonical credential
        # stores / browser profiles / mailboxes even if a YARA rule is
        # convinced they're malicious. See _DEFAULT_QUARANTINE_ALLOW_*
        # for the full list and the rationale.
        allow_match = _is_quarantine_allowed(
            filepath, extra_substrings=self._quarantine_allow_extra,
        )
        if allow_match is not None:
            logger.warning(
                f"QUARANTINE BLOCKED [{allow_match}]: {filepath} "
                f"(case={case.get('case_id')})"
            )
            self.bus.publish(Event(
                category=EventCategory.RESPONSE_QUARANTINE,
                severity=Severity.MEDIUM,
                source="response",
                data={
                    "action": "quarantine_blocked",
                    "case_id": case.get("case_id"),
                    "parent_case_id": parent_case_id,
                    "original_path": str(filepath),
                    "allow_list_match": allow_match,
                    "reason": reason,
                    "rule_id": rule_id,
                },
            ))
            return None

        try:
            file_size = os.path.getsize(filepath)
            sha256 = _hash_file_chunked(filepath)

            # Sibling quarantines get their own case_id, linked to parent.
            if parent_case_id is None:
                case_id = case.get("case_id", "nocase")
            else:
                case_id = uuid.uuid4().hex[:12]

            timestamp = int(time.time())
            # Monotonic counter suffix avoids filename collisions when
            # primary + several siblings are all quarantined in the same
            # second (common when siblings are small).
            quarantine_name = (
                f"{timestamp}_{case_id}_{sha256[:16]}_{Path(filepath).name}"
            )
            quarantine_path = self.quarantine_dir / quarantine_name
            if quarantine_path.exists():
                quarantine_name = (
                    f"{timestamp}_{case_id}_{sha256[:16]}_"
                    f"{uuid.uuid4().hex[:4]}_{Path(filepath).name}"
                )
                quarantine_path = self.quarantine_dir / quarantine_name

            metadata = {
                "case_id": case_id,
                "parent_case_id": parent_case_id,
                "detection_event_id": case.get("detection_event_id"),
                "original_path": str(filepath),
                "sha256": sha256,
                "size": file_size,
                "quarantined_at": time.time(),
                "reason": reason,
                "rule_id": rule_id,
                "mitre_attack": case.get("mitre_attack", ""),
                "original_permissions": oct(os.stat(filepath).st_mode),
                "state": "STAGED",
                # Only the primary carries the execution chain — siblings
                # reference it via parent_case_id so we don't duplicate
                # potentially large snapshots across N sibling metas.
                "execution_chain": (
                    case.get("execution_chain") if parent_case_id is None
                    else None
                ),
            }
            meta_path = self.quarantine_dir / f"{quarantine_name}.meta.json"
            meta_path.write_text(json.dumps(metadata, indent=2, default=str))

            shutil.move(filepath, str(quarantine_path))
            _lock_quarantined_file(str(quarantine_path))

            label = f"case={case_id}"
            if parent_case_id:
                label = f"sibling of {parent_case_id} (case={case_id})"
            logger.warning(f"QUARANTINED [{label}]: {filepath} → {quarantine_path}")

            self.bus.publish(Event(
                category=EventCategory.RESPONSE_QUARANTINE,
                severity=Severity.HIGH,
                source="response",
                data={
                    "action": "file_quarantined",
                    "case_id": case_id,
                    "parent_case_id": parent_case_id,
                    "original_path": str(filepath),
                    "quarantine_path": str(quarantine_path),
                    "meta_path": str(meta_path),
                    "sha256": sha256,
                    "size": file_size,
                    "case": case if parent_case_id is None else {
                        "case_id": case_id,
                        "parent_case_id": parent_case_id,
                    },
                },
            ))

            return {
                "case_id": case_id,
                "parent_case_id": parent_case_id,
                "sha256": sha256,
                "size": file_size,
                "quarantine_path": str(quarantine_path),
                "meta_path": str(meta_path),
                "original_path": str(filepath),
            }

        except Exception as e:
            logger.error(f"Quarantine failed for {filepath}: {e}")
            return None

    def _run_hash_sweep(self, primary: dict, case: dict):
        """Sweep drop zones for files whose SHA-256 matches `primary`.
        Each match is quarantined with parent_case_id = primary case."""
        zones = (self._hash_sweep_zones_override
                 if self._hash_sweep_zones_override is not None
                 else resolve_default_drop_zones())
        if not zones:
            return

        parent_case_id = primary["case_id"]
        try:
            report = sweep_for_siblings(
                target_hash=primary["sha256"],
                target_size=primary["size"],
                drop_zones=zones,
                excluded_paths=self._hash_sweep_excluded,
                time_budget_s=self.hash_sweep_time_budget_s,
                max_file_size_mb=self.hash_sweep_max_file_mb,
                max_depth=self.hash_sweep_max_depth,
            )
        except Exception as e:
            logger.error(f"Hash sweep failed: {e}", exc_info=True)
            return

        siblings: list[dict] = []
        for match_path in report["matches"]:
            sib = self._quarantine_path(
                str(match_path), case,
                reason=f"sibling of case {parent_case_id}",
                rule_id=primary.get("rule_id", ""),
                parent_case_id=parent_case_id,
            )
            if sib:
                siblings.append({
                    "case_id": sib["case_id"],
                    "original_path": sib["original_path"],
                    "quarantine_path": sib["quarantine_path"],
                    "sha256": sib["sha256"],
                })

        # Append sibling refs to the primary meta.json so an operator
        # reading one case file sees the full scope of the incident.
        if siblings:
            try:
                meta_path = Path(primary["meta_path"])
                meta = json.loads(meta_path.read_text())
                meta["siblings"] = siblings
                meta_path.write_text(json.dumps(meta, indent=2, default=str))
            except Exception as e:
                logger.warning(f"Failed to append siblings to primary meta: {e}")

        self.bus.publish(Event(
            category=EventCategory.RESPONSE_QUARANTINE,
            severity=Severity.INFO,
            source="response",
            data={
                "action": "hash_sweep_complete",
                "case_id": parent_case_id,
                "target_sha256": primary["sha256"],
                "siblings_found": len(siblings),
                "siblings": siblings,
                "scanned": report["scanned"],
                "hashed": report["hashed"],
                "skipped_large": report["skipped_large"],
                "errors": report["errors"],
                "elapsed_s": report["elapsed_s"],
                "budget_exhausted": report["budget_exhausted"],
                "zones_walked": report["zones_walked"],
            },
        ))

        return siblings

    def _run_persistence_hunt(self, primary: dict, siblings: list[dict]):
        """Scan OS persistence surfaces for references to the quarantined
        file(s). Publishes a single summary event + appends hits to the
        primary meta.json. Remediation is intentionally out of scope here;
        auto-removing persistence entries is how defenders brick systems.
        """
        indicators = build_indicators_from_quarantine(primary, siblings)
        try:
            report = hunt_persistence(
                indicators,
                roots=self._persistence_roots,
                platform=self._persistence_platform,
            )
        except Exception as e:
            logger.error(f"Persistence hunt failed: {e}", exc_info=True)
            return

        hits = report.get("hits", [])
        if hits:
            # Stamp the primary case id on every hit so operators can join
            # a persistence record back to the originating quarantine.
            parent_case_id = primary["case_id"]
            for h in hits:
                h["case_id"] = parent_case_id

            # Append to primary meta.json.
            try:
                meta_path = Path(primary["meta_path"])
                meta = json.loads(meta_path.read_text())
                meta["persistence_hits"] = hits
                meta_path.write_text(json.dumps(meta, indent=2, default=str))
            except Exception as e:
                logger.warning(f"Failed to append persistence to meta: {e}")

            logger.warning(
                f"PERSISTENCE [case={parent_case_id}]: {len(hits)} hit(s) "
                f"across {len(set(h['surface'] for h in hits))} surface(s)"
            )

        self.bus.publish(Event(
            category=EventCategory.RESPONSE_PERSISTENCE,
            severity=Severity.HIGH if hits else Severity.INFO,
            source="response",
            data={
                "action": "persistence_hunt_complete",
                "case_id": primary["case_id"],
                "hits_found": len(hits),
                "hits": hits,
                "surfaces_scanned": report.get("surfaces_scanned", []),
                "surfaces_failed": report.get("surfaces_failed", []),
                "indicator_count": report.get("indicator_count", 0),
            },
        ))

    def _run_hardening_recheck(self, primary: dict):
        """Re-audit hardening posture, diff against baseline, publish one
        response.hardening_drift event per NEW finding plus one summary.

        First-run behaviour: when no baseline exists on disk, every current
        finding becomes 'new' — that's intentional. Operators get one
        loud drift batch on first install, then it quiets to actual deltas.
        """
        case_id = primary.get("case_id", "nocase")
        try:
            result = _run_hardening_recheck(
                self.hardening_baseline_path,
                runner=self._hardening_runner,
                runner_factory=self._hardening_runner_factory,
                update_baseline=True,
                platform=self.hardening_recheck_platform,
            )
        except Exception as e:
            logger.error(f"Hardening re-check failed: {e}", exc_info=True)
            return

        if result.get("status") != "ok":
            self.bus.publish(Event(
                category=EventCategory.RESPONSE_HARDENING_DRIFT,
                severity=Severity.LOW,
                source="response",
                data={"action": "hardening_recheck_failed",
                      "case_id": case_id, **result},
            ))
            return

        diff = result["diff"]
        baseline_existed = result["baseline_existed"]

        for finding in diff["new"]:
            sev = self._drift_severity(finding, baseline_existed)
            self.bus.publish(Event(
                category=EventCategory.RESPONSE_HARDENING_DRIFT,
                severity=sev,
                source="response",
                data={
                    "action": "hardening_drift",
                    "case_id": case_id,
                    "drift_kind": "new",
                    "finding": finding,
                    "first_baseline": not baseline_existed,
                },
            ))

        if diff["new"]:
            logger.warning(
                f"HARDENING DRIFT [case={case_id}]: {len(diff['new'])} new, "
                f"{result['resolved_count']} resolved, "
                f"{result['persistent_count']} persistent"
            )

        self.bus.publish(Event(
            category=EventCategory.RESPONSE_HARDENING_DRIFT,
            severity=Severity.HIGH if diff["new"] and baseline_existed
                     else Severity.INFO,
            source="response",
            data={
                "action": "hardening_recheck_complete",
                "case_id": case_id,
                "baseline_existed": baseline_existed,
                "baseline_written": result["baseline_written"],
                "baseline_path": result["baseline_path"],
                "current_total": result["current_total"],
                "new_count": result["new_count"],
                "resolved_count": result["resolved_count"],
                "persistent_count": result["persistent_count"],
                "resolved": diff["resolved"],
            },
        ))

    def _drift_severity(self, finding: dict, baseline_existed: bool) -> Severity:
        """Map a finding's severity to an event severity. First-run
        baselines downgrade to INFO — they're not real drift, just
        the initial census."""
        if not baseline_existed:
            return Severity.INFO
        sev = (finding.get("severity") or "").lower()
        return {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }.get(sev, Severity.MEDIUM)

    def hardening_recheck(self, *, update_baseline: bool = True) -> dict:
        """Operator-triggered re-check (no detection required). Useful for
        a 'scan now' button or scheduled posture sweep."""
        try:
            result = _run_hardening_recheck(
                self.hardening_baseline_path,
                runner=self._hardening_runner,
                runner_factory=self._hardening_runner_factory,
                update_baseline=update_baseline,
                platform=self.hardening_recheck_platform,
            )
        except Exception as e:
            logger.error(f"Hardening re-check failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
        self.bus.publish(Event(
            category=EventCategory.RESPONSE_HARDENING_DRIFT,
            severity=Severity.INFO,
            source="response",
            data={"action": "hardening_recheck_manual",
                  "operator": "operator", **{
                      k: v for k, v in result.items() if k != "diff"
                  }},
        ))
        return result

    def _forensic_snapshot(self, event: Event, case: dict):
        """Capture full system state for post-incident analysis."""
        timestamp = int(time.time())
        case_id = case.get("case_id", "nocase")
        snapshot_path = self.forensics_dir / f"snapshot_{timestamp}_{case_id}.json"

        try:
            snapshot = {
                "timestamp": time.time(),
                "case": case,
                "trigger_event": event.to_dict(),
                "processes": [],
                "network_connections": [],
                "listeners": [],
            }

            # Capture all processes
            for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline",
                                              "username", "create_time", "status",
                                              "cpu_percent", "memory_info"]):
                try:
                    info = proc.info
                    cmdline = info.get("cmdline") or []
                    mem = info.get("memory_info")
                    snapshot["processes"].append({
                        "pid": info["pid"],
                        "ppid": info.get("ppid", 0),
                        "name": info.get("name", ""),
                        "cmdline": " ".join(cmdline),
                        "username": info.get("username", ""),
                        "cpu_percent": info.get("cpu_percent", 0),
                        "memory_mb": round(mem.rss / 1024 / 1024, 2) if mem else 0,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Capture network state
            for conn in psutil.net_connections(kind="inet"):
                try:
                    entry = {
                        "status": conn.status,
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "pid": conn.pid,
                    }
                    if conn.status == "LISTEN":
                        snapshot["listeners"].append(entry)
                    else:
                        snapshot["network_connections"].append(entry)
                except Exception:
                    continue

            snapshot_path.write_text(json.dumps(snapshot, indent=2, default=str))
            logger.info(f"Forensic snapshot saved: {snapshot_path}")

            self.bus.publish(Event(
                category=EventCategory.RESPONSE_FORENSIC,
                severity=Severity.INFO,
                source="response",
                data={
                    "action": "forensic_snapshot",
                    "case_id": case_id,
                    "path": str(snapshot_path),
                    "processes": len(snapshot["processes"]),
                    "connections": len(snapshot["network_connections"]),
                },
            ))

        except Exception as e:
            logger.error(f"Forensic snapshot failed: {e}", exc_info=True)

    def _alert(self, event: Event, case: dict):
        """Publish an alert event."""
        self.bus.publish(Event(
            category=EventCategory.RESPONSE_ALERT,
            severity=event.severity,
            source="response",
            data={
                "action": "alert",
                "rule_id": event.data.get("rule_id", ""),
                "rule_name": event.data.get("rule_name", event.data.get("rule", "")),
                "description": event.data.get("description", ""),
                "mitre_attack": event.mitre_attack,
                "original_source": event.source,
                "summary": self._build_summary(event),
                "case_id": case.get("case_id"),
                "case": case,
            },
        ))

    def _log_detection(self, event: Event):
        """Log detection for record keeping."""
        logger.info(f"DETECTION LOG: [{event.severity.value.upper()}] "
                     f"rule={event.data.get('rule_id', 'N/A')} "
                     f"source={event.source}")

    def _build_summary(self, event: Event) -> str:
        """Build a human-readable alert summary."""
        parts = []
        if rule_name := event.data.get("rule_name", event.data.get("rule", "")):
            parts.append(f"Rule: {rule_name}")
        if pid := event.data.get("pid", event.data.get("source_event", {}).get("pid")):
            parts.append(f"PID: {pid}")
        if filepath := event.data.get("filepath", event.data.get("path", "")):
            parts.append(f"File: {filepath}")
        if mitre := event.mitre_attack:
            parts.append(f"ATT&CK: {mitre}")
        return " | ".join(parts) if parts else "Detection event"

    @property
    def is_running(self) -> bool:
        return self._running
