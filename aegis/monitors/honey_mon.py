"""
AEGIS Honeytoken Monitor
========================
Plant decoy files in attacker-attractive locations and watch for any
modification or deletion. Two real attacker behaviours light this up:

  * Ransomware encrypts every file it can — a canary `wallet.dat` flips
    in seconds, well before encryption finishes against real data.
  * Credential thieves grep recursively for `credentials.txt` /
    `aws/credentials` / `id_rsa*` — touching one of those is the
    single highest-confidence detection in the whole project.

Why this works
--------------
Honeytokens have a near-zero baseline FP rate by construction. The
canary files are unreferenced by any legitimate process; *anything*
that mutates them is, with very high probability, hostile or a
generic filesystem-walking tool that just earned itself a forensic
capture and quarantine of whatever spawned the walker.

What this monitor does NOT do (yet)
-----------------------------------
Detecting *reads* of a canary requires Windows SACL audit policy or
the Linux audit subsystem; both are out of scope for the poll-based
architecture and would need ETW (Windows) or auditd (Linux) hooks.
v1 watches mutations + deletions, which catches the two attacker
behaviours above while keeping the polling overhead negligible.

Detection events
----------------
  detection.honeytoken      severity=HIGH    canary tripped
    data.action ∈
      "canary_modified"   sha256 changed OR sentinel marker missing
      "canary_deleted"    file disappeared between polls
      "canary_unreadable" file present but unreadable (perm flip,
                          locked by another process, …)

  detection.honeytoken      severity=INFO    operator audit only
    data.action == "canary_planted"      first plant
    data.action == "canary_replanted"    auto_replant restored a deleted canary
"""

from __future__ import annotations

import os
import json
import time
import uuid
import logging
import secrets
import hashlib
import threading
import platform
from pathlib import Path
from typing import Optional

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.honey")


# ── Canary content templates ────────────────────────────────────────
# Keep them small and plausible. The trailing sentinel line is the
# secondary integrity signal — if an attacker rewrites the file with
# their own content, the sentinel is gone even before sha256 is
# checked. {sentinel} is unique per canary.

_TEMPLATE_AWS_CREDS = (
    "[default]\n"
    "aws_access_key_id = AKIA{fake_key}\n"
    "aws_secret_access_key = {fake_secret}\n"
    "region = us-east-1\n"
    "# {sentinel}\n"
)

_TEMPLATE_SSH_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "{fake_b64}\n"
    "-----END RSA PRIVATE KEY-----\n"
    "# {sentinel}\n"
)

_TEMPLATE_PASSWORDS = (
    "Banking login: alice@corp.local / {fake_pwd_a}\n"
    "VPN: contractor / {fake_pwd_b}\n"
    "Mailbox recovery code: {fake_pwd_c}\n"
    "# {sentinel}\n"
)

_TEMPLATE_WALLET = (
    "BITCOIN-WALLET-V1\n"
    "{fake_blob}\n"
    "# {sentinel}\n"
)

_TEMPLATE_TAX = (
    "FORM-1040 SUMMARY (synthetic)\n"
    "{fake_blob}\n"
    "# {sentinel}\n"
)

_TEMPLATES: dict[str, str] = {
    "aws_creds": _TEMPLATE_AWS_CREDS,
    "ssh_key": _TEMPLATE_SSH_KEY,
    "passwords": _TEMPLATE_PASSWORDS,
    "wallet": _TEMPLATE_WALLET,
    "tax": _TEMPLATE_TAX,
}


def _render(template_name: str, sentinel: str) -> bytes:
    """Materialise a canary body. Random bytes use `secrets` so a
    template never produces the same body twice — a static body would
    let an attacker fingerprint AEGIS by content hash."""
    tpl = _TEMPLATES[template_name]
    body = tpl.format(
        sentinel=sentinel,
        fake_key=secrets.token_hex(8).upper(),
        fake_secret=secrets.token_urlsafe(28),
        fake_b64="\n".join(
            secrets.token_urlsafe(48) for _ in range(12)
        ),
        fake_pwd_a=secrets.token_urlsafe(8),
        fake_pwd_b=secrets.token_urlsafe(8),
        fake_pwd_c=secrets.token_urlsafe(8),
        fake_blob=secrets.token_hex(256),
    )
    return body.encode("utf-8")


def _default_canary_set() -> list[tuple[Path, str]]:
    """Per-platform default canary paths. Resolved against $USERPROFILE
    or $HOME; this is the bait set the v1 audit recommended."""
    if platform.system().lower() == "windows":
        home = Path(os.environ.get("USERPROFILE") or Path.home())
        return [
            (home / "Documents" / "passwords.txt", "passwords"),
            (home / "Documents" / "IT_credentials.txt", "passwords"),
            (home / "Documents" / "wallet.dat", "wallet"),
            (home / "Documents" / "Tax_Returns_2025.pdf", "tax"),
            (home / "Desktop" / "TODO_credentials.txt", "passwords"),
            (home / "Downloads" / "company_payroll_q4.csv", "passwords"),
            (home / ".aws" / "credentials", "aws_creds"),
            (home / ".ssh" / "id_rsa.bak", "ssh_key"),
        ]
    home = Path.home()
    return [
        (home / "Documents" / "passwords.txt", "passwords"),
        (home / "Documents" / "wallet.dat", "wallet"),
        (home / ".aws" / "credentials", "aws_creds"),
        (home / ".ssh" / "id_rsa.bak", "ssh_key"),
        (home / "backup_codes.txt", "passwords"),
    ]


# ── Monitor ─────────────────────────────────────────────────────────

class HoneytokenMonitor:
    """Plants canary files (idempotently) and polls them for tampering.

    Baseline manifest at `data/honey.baseline.json` records every
    planted canary's sha256, size, and sentinel. The monitor will NOT
    overwrite a pre-existing file at a canary path — operator data is
    sacred and we'd rather miss a slot than smash a real file.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.poll_interval_s = float(
            self.config.get("poll_interval_seconds", 60)
        )
        self.baseline_path = Path(self.config.get(
            "baseline_path", "data/honey.baseline.json",
        ))
        self.plant_on_start = bool(self.config.get("plant_on_start", True))
        self.plant_user_dirs = bool(self.config.get("plant_user_dirs", True))
        self.auto_replant = bool(self.config.get("auto_replant", False))
        # Operator-supplied extra canaries: list of {"path": "...",
        # "template": "passwords"|"aws_creds"|...}.
        self.extra_canaries: list[dict] = list(
            self.config.get("extra_canaries", []) or []
        )

        # path -> {sha256, size, sentinel, template, planted_at}
        self._baseline: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    # -- public ------------------------------------------------------
    def start(self):
        if not self.config.get("enabled", True):
            logger.info("HoneytokenMonitor disabled in config")
            return

        self._load_baseline()
        if self.plant_on_start:
            self._plant_missing()

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="aegis-honey",
        )
        self._thread.start()
        logger.info(
            f"HoneytokenMonitor started "
            f"(canaries={len(self._baseline)}, poll={self.poll_interval_s}s)"
        )

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "canaries": len(self._baseline),
                "running": self._running,
            }

    # -- baseline ----------------------------------------------------
    def _load_baseline(self) -> None:
        if not self.baseline_path.exists():
            return
        try:
            data = json.loads(self.baseline_path.read_text())
            if isinstance(data, dict):
                self._baseline = data
                logger.info(
                    f"HoneytokenMonitor: loaded baseline "
                    f"({len(self._baseline)} canaries)"
                )
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(
                f"HoneytokenMonitor: baseline unreadable, will re-plant: {e}"
            )
            self._baseline = {}

    def _persist_baseline(self) -> None:
        try:
            self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.baseline_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._baseline, indent=2, default=str))
            os.replace(tmp, self.baseline_path)
        except OSError as e:
            logger.warning(f"HoneytokenMonitor: persist baseline failed: {e}")

    # -- planting ----------------------------------------------------
    def _desired_canary_set(self) -> list[tuple[Path, str]]:
        canaries: list[tuple[Path, str]] = []
        if self.plant_user_dirs:
            canaries.extend(_default_canary_set())
        for entry in self.extra_canaries:
            try:
                p = Path(entry["path"]).expanduser()
                tpl = entry["template"]
                if tpl not in _TEMPLATES:
                    logger.warning(
                        f"HoneytokenMonitor: unknown template '{tpl}' for "
                        f"{p}; skipping"
                    )
                    continue
                canaries.append((p, tpl))
            except (KeyError, TypeError) as e:
                logger.warning(
                    f"HoneytokenMonitor: bad extra_canaries entry {entry}: {e}"
                )
        return canaries

    def _plant_one(self, path: Path, template: str) -> Optional[dict]:
        """Create a canary file. Refuse to overwrite a pre-existing
        file — better to skip than damage operator data."""
        if path.exists():
            logger.info(
                f"honey: target {path} already exists; skipping plant"
            )
            return None
        sentinel = f"AEGIS-HONEY-CANARY-{uuid.uuid4().hex}"
        body = _render(template, sentinel)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        except OSError as e:
            logger.warning(f"honey: could not plant {path}: {e}")
            return None
        return {
            "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body),
            "sentinel": sentinel,
            "template": template,
            "planted_at": time.time(),
        }

    def _plant_missing(self) -> None:
        """First-run + auto-replant entry. Plants every canary in the
        desired set whose path is not already in the baseline."""
        changed = False
        with self._lock:
            for path, template in self._desired_canary_set():
                key = str(path)
                if key in self._baseline:
                    continue
                entry = self._plant_one(path, template)
                if entry is None:
                    continue
                self._baseline[key] = entry
                changed = True
                self._publish_audit(
                    "canary_planted", path=key, entry=entry,
                )
        if changed:
            self._persist_baseline()

    def _replant(self, path: str) -> None:
        with self._lock:
            template = (self._baseline.get(path) or {}).get("template")
        if not template:
            return
        entry = self._plant_one(Path(path), template)
        if entry is None:
            return
        with self._lock:
            self._baseline[path] = entry
        self._persist_baseline()
        self._publish_audit("canary_replanted", path=path, entry=entry)

    # -- detection ---------------------------------------------------
    def _check_one(self, path: str, expected: dict) -> Optional[dict]:
        p = Path(path)
        if not p.exists():
            return {
                "action": "canary_deleted",
                "path": path,
                "expected_sha256": expected.get("sha256"),
                "template": expected.get("template"),
            }
        try:
            body = p.read_bytes()
        except OSError as e:
            return {
                "action": "canary_unreadable",
                "path": path,
                "error": str(e),
                "template": expected.get("template"),
            }
        actual_sha = hashlib.sha256(body).hexdigest()
        if actual_sha == expected.get("sha256"):
            return None
        sentinel = expected.get("sentinel", "")
        sentinel_present = bool(sentinel) and sentinel.encode() in body
        return {
            "action": "canary_modified",
            "path": path,
            "expected_sha256": expected.get("sha256"),
            "actual_sha256": actual_sha,
            "expected_size": expected.get("size"),
            "actual_size": len(body),
            "sentinel_present": sentinel_present,
            "template": expected.get("template"),
        }

    def check_once(self) -> list[dict]:
        """Run a single inspection pass. Public for tests + operator
        CLI; the loop calls this on every tick."""
        events: list[dict] = []
        with self._lock:
            items = list(self._baseline.items())
        for path, expected in items:
            try:
                change = self._check_one(path, expected)
            except Exception as e:
                logger.error(f"honey: check {path} failed: {e}", exc_info=True)
                continue
            if change is None:
                continue
            self._publish_change(change)
            events.append(change)
            if change["action"] == "canary_deleted" and self.auto_replant:
                self._replant(path)
        return events

    def _loop(self) -> None:
        while self._running:
            self.check_once()
            slept = 0.0
            while self._running and slept < self.poll_interval_s:
                time.sleep(1.0)
                slept += 1.0

    # -- publish -----------------------------------------------------
    def _publish_change(self, change: dict) -> None:
        # Honeytoken trips map to T1083 (File and Directory Discovery)
        # — we don't know the attacker's eventual goal, only that they
        # walked a path no legitimate process walks.
        self.bus.publish(Event(
            category=EventCategory.DETECTION_HONEYTOKEN,
            severity=Severity.HIGH,
            source="honey",
            mitre_attack="T1083",
            data={
                "rule_name": "Honeytoken tripped",
                "rule_id": f"HONEY-{change['action'].upper()}",
                **change,
            },
        ))
        logger.warning(
            f"HONEY {change['action'].upper()} {change['path']} "
            f"(template={change.get('template')})"
        )

    def _publish_audit(self, action: str, *, path: str, entry: dict) -> None:
        self.bus.publish(Event(
            category=EventCategory.DETECTION_HONEYTOKEN,
            severity=Severity.INFO,
            source="honey",
            data={
                "rule_name": "Honeytoken audit",
                "rule_id": f"HONEY-{action.upper()}",
                "action": action,
                "path": path,
                "template": entry.get("template"),
                "sha256": entry.get("sha256"),
                "size": entry.get("size"),
            },
        ))
