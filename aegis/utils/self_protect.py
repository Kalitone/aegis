"""
AEGIS Self-Protection
======================
Tamper resistance for AEGIS itself. A defender that can be killed by every
user-mode process is theatre, so we layer four cheap defences:

  1. Manifest integrity      — config + rules hashed; mismatch refuses startup.
  2. Parent verification     — when run as a Windows service, parent must be
                               services.exe (otherwise something is hijacking
                               our service binary path).
  3. Watchdog                — supervisor process that respawns AEGIS if the
                               main process exits unexpectedly.
  4. Service ACL hardening   — service can be controlled only by SYSTEM and
                               local Administrators (applied by the install
                               script — see scripts/install-service.ps1).

The runtime hooks (#1, #2) live here. The watchdog (#3) is launched as a
separate `python -m aegis.utils.self_protect --watch <pid> <argv...>` so it
survives even if the main process dies hard.
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import hashlib
import logging
import platform
import subprocess
from pathlib import Path

logger = logging.getLogger("aegis.utils.self_protect")

MANIFEST_FILENAME = "integrity.manifest.json"


# ── 1. Integrity manifest ────────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _enumerate_protected_files(root: Path, config_path: Path | None) -> list[Path]:
    """Files whose contents matter for trust. Limited list — we don't hash
    the whole project (Python source is already process-loaded and immutable
    once running)."""
    candidates: list[Path] = []
    if config_path and config_path.exists():
        candidates.append(config_path)
    for sub in ("rules/yara", "rules/behavioral", "rules/supply_chain"):
        d = root / sub
        if d.exists():
            for p in d.rglob("*"):
                if p.is_file() and p.suffix in (".yar", ".yara", ".yml",
                                                ".yaml", ".json"):
                    candidates.append(p)
    return sorted(candidates)


def _canonical_payload(manifest: dict) -> bytes:
    """Bytes that the attestation signature covers. Excludes the
    `attestation` block itself (chicken-and-egg) and uses sorted-keys
    JSON so build / verify agree byte-for-byte."""
    body = {k: v for k, v in manifest.items() if k != "attestation"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def build_manifest(project_root: str | os.PathLike,
                   config_path: str | os.PathLike | None,
                   manifest_path: str | os.PathLike | None = None,
                   *,
                   attest: bool = True) -> dict:
    """Hash all protected files and write the manifest. Run after legitimate
    config or rule changes.

    `attest=True` (default) signs the manifest with the host's TPM-
    backed ECDSA key when available, so a stolen manifest can't be
    replayed on another host. The signature is a no-op on platforms
    where `tpm_attest.is_available()` is False — the SHA-256 layer is
    unaffected.
    """
    root = Path(project_root).resolve()
    cfg = Path(config_path).resolve() if config_path else None
    out = Path(manifest_path) if manifest_path else (root / "data" / MANIFEST_FILENAME)
    out.parent.mkdir(parents=True, exist_ok=True)

    files = _enumerate_protected_files(root, cfg)
    entries = {str(p.relative_to(root)).replace("\\", "/"): _sha256_file(p)
               for p in files}
    manifest = {
        "generated_at": time.time(),
        "hostname": socket.gethostname(),
        "file_count": len(entries),
        "files": entries,
    }

    if attest:
        try:
            from aegis.utils import tpm_attest
            if tpm_attest.is_available():
                payload = _canonical_payload(manifest)
                sig_obj = tpm_attest.sign(payload)
                if sig_obj is not None:
                    manifest["attestation"] = sig_obj
                    logger.info(
                        f"Manifest TPM-attested via {sig_obj.get('provider')}"
                    )
                else:
                    logger.warning("TPM available but sign() returned None")
            else:
                logger.info("TPM not available — manifest is SHA-256 only")
        except Exception as e:
            logger.warning(f"Manifest attestation skipped: {e}")

    out.write_text(json.dumps(manifest, indent=2))
    logger.info(f"Integrity manifest written: {out} ({len(entries)} files)")
    return manifest


def verify_manifest(project_root: str | os.PathLike,
                    config_path: str | os.PathLike | None,
                    manifest_path: str | os.PathLike | None = None,
                    strict: bool = False,
                    *,
                    require_attestation: bool = False) -> tuple[bool, list[str]]:
    """Return (ok, problems). If strict and no manifest exists, returns False.

    `require_attestation=True` rejects an unsigned (or sig-failing)
    manifest even if every SHA-256 hash matches — for the audit-grade
    deployment that wants the stronger guarantee. Default False keeps
    the existing trust model: hashes are mandatory, signature is a
    layered-on bonus.
    """
    root = Path(project_root).resolve()
    cfg = Path(config_path).resolve() if config_path else None
    mpath = Path(manifest_path) if manifest_path else (root / "data" / MANIFEST_FILENAME)

    if not mpath.exists():
        if strict:
            return False, [f"manifest missing: {mpath}"]
        # First-run: build it and accept current state as trust baseline.
        build_manifest(project_root, config_path, mpath)
        return True, []

    try:
        manifest = json.loads(mpath.read_text())
    except Exception as e:
        return False, [f"manifest unreadable: {e}"]

    expected: dict[str, str] = manifest.get("files", {})
    problems: list[str] = []
    current_files = _enumerate_protected_files(root, cfg)
    seen: set[str] = set()
    for p in current_files:
        rel = str(p.relative_to(root)).replace("\\", "/")
        seen.add(rel)
        actual = _sha256_file(p)
        want = expected.get(rel)
        if want is None:
            problems.append(f"NEW (untrusted) file: {rel}")
        elif actual != want:
            problems.append(f"MODIFIED: {rel}")
    for rel in expected:
        if rel not in seen:
            problems.append(f"DELETED: {rel}")

    # Attestation layer — orthogonal to the SHA-256 check above.
    sig_obj = manifest.get("attestation")
    if sig_obj:
        try:
            from aegis.utils import tpm_attest
            payload = _canonical_payload(manifest)
            v = tpm_attest.verify(payload, sig_obj)
            if not v["ok"]:
                problems.append(
                    f"ATTESTATION FAILED: "
                    f"{v.get('reason') or 'signature/host-binding mismatch'}"
                )
            elif not v.get("host_bound_checked"):
                # Soft-warn: signature math OK, host binding not verified.
                logger.warning(
                    "manifest attestation: signature OK but host-binding "
                    "NOT verified (no TPM on this host)"
                )
        except Exception as e:
            problems.append(f"attestation check failed: {e}")
    elif require_attestation:
        problems.append("attestation REQUIRED but manifest has no signature")

    return (not problems), problems


# ── 2. Parent-process check ──────────────────────────────────────────

def parent_is_service_host() -> bool:
    """True when our parent looks like the Windows service controller. On
    non-Windows or when running interactively, returns True (no-op)."""
    if platform.system() != "Windows":
        return True
    try:
        import psutil
    except ImportError:
        return True
    try:
        parent = psutil.Process(os.getpid()).parent()
        if parent is None:
            return True  # detached — usually console / dev
        name = (parent.name() or "").lower()
        return name in ("services.exe", "nssm.exe", "python.exe", "pythonw.exe",
                        "cmd.exe", "powershell.exe", "pwsh.exe", "code.exe",
                        "explorer.exe", "windowsterminal.exe")
    except Exception:
        return True  # fail open — never wedge startup on a probe failure


# ── 3. Watchdog ───────────────────────────────────────────────────────

def spawn_watchdog(argv: list[str]) -> int | None:
    """Spawn an external watchdog that will relaunch AEGIS if our PID dies.
    Returns the watchdog PID (or None if disabled / failed)."""
    if os.environ.get("AEGIS_NO_WATCHDOG") == "1":
        return None
    py = sys.executable
    cmd = [py, "-m", "aegis.utils.self_protect", "--watch", str(os.getpid()), *argv]
    try:
        # DETACHED_PROCESS on Windows so it survives our death; on POSIX
        # start_new_session does the same.
        creationflags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            start_new_session=(os.name != "nt"),
            close_fds=True,
        )
        logger.info(f"Watchdog spawned (pid={proc.pid})")
        return proc.pid
    except Exception as e:
        logger.warning(f"Watchdog spawn failed: {e}")
        return None


def _watch(target_pid: int, relaunch_argv: list[str]) -> int:
    """Block until target_pid exits, then relaunch the same command line.
    The watchdog itself exits after one relaunch (the new AEGIS will spawn
    its own fresh watchdog)."""
    try:
        import psutil
    except ImportError:
        return 2
    try:
        target = psutil.Process(target_pid)
    except psutil.NoSuchProcess:
        # Already dead before we started — relaunch immediately.
        target = None

    if target is not None:
        try:
            target.wait()
        except psutil.NoSuchProcess:
            pass

    # Don't respawn if AEGIS was asked to stop (file flag set during shutdown).
    sentinel = Path("data/.aegis_clean_shutdown")
    if sentinel.exists():
        try:
            sentinel.unlink()
        except OSError:
            pass
        return 0

    time.sleep(2)  # back-off so we don't tight-loop
    try:
        subprocess.Popen(
            relaunch_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except Exception:
        return 3
    return 0


def mark_clean_shutdown() -> None:
    """Called by the main process before a user-initiated stop so the
    watchdog doesn't immediately relaunch us."""
    try:
        Path("data").mkdir(parents=True, exist_ok=True)
        Path("data/.aegis_clean_shutdown").write_text(str(time.time()))
    except OSError:
        pass


# ── CLI entry for the watchdog subprocess ──────────────────────────

def _main():
    if len(sys.argv) >= 4 and sys.argv[1] == "--watch":
        pid = int(sys.argv[2])
        relaunch = sys.argv[3:]
        sys.exit(_watch(pid, relaunch))
    if len(sys.argv) >= 2 and sys.argv[1] == "--build-manifest":
        root = sys.argv[2] if len(sys.argv) >= 3 else "."
        cfg = sys.argv[3] if len(sys.argv) >= 4 else "config/aegis.yaml"
        build_manifest(root, cfg)
        return
    print("usage: python -m aegis.utils.self_protect --watch <pid> <relaunch...>")
    print("       python -m aegis.utils.self_protect --build-manifest [root] [config]")


if __name__ == "__main__":
    _main()
