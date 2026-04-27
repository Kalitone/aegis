"""
AEGIS Response — Persistence Hunting
=====================================
Given a quarantined file's indicators (paths, hashes, basenames), scan
every OS persistence surface we know about and report references.

This is the step that takes AEGIS from "removes the file" to "finds the
root cause." A file that keeps respawning is a persistence mechanism
pointing at it; "quarantining" that same file repeatedly is a symptom
treatment that pretends to be a cure.

Commercial parallels:
  * Sysinternals Autoruns (enumeration baseline)
  * ESET "persistence check"
  * Kaspersky "autorun inspection"
  * CrowdStrike Falcon "persistence mechanism" enrichment

Scope v1 (detection only — removal is a separate policy gate):

  Windows
    - HKCU/HKLM \\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKCU/HKLM \\...\\RunOnce
    - Startup folders (user + all-users)
    - Scheduled Tasks (via schtasks CSV enumeration)

  POSIX
    - /etc/crontab, /etc/cron.* , /var/spool/cron/* , user crontab -l
    - systemd unit files (system + user)
    - /etc/rc.local, /etc/init.d/*
    - Shell profiles (/etc/profile, bash/zsh rc, /etc/profile.d/*)
    - /etc/ld.so.preload

Design choices
--------------
  * Dependency injection: every file-based surface accepts a `roots`
    override so tests plant fake artifacts in a temp dir instead of
    mutating real /etc or the registry.
  * Conservative matching: path (full), hash (exact), basename (only if
    6+ chars — shorter names produce too many false positives in
    real-world profile scripts).
  * Line-level hit granularity: operators get the offending line number
    and the reference string, not just "something matched in this file."
  * Graceful degradation: individual surface failures (missing binary,
    permission denied) are reported in `surfaces_failed` but never
    abort the overall hunt.
  * Report-only: every hit carries `removable: False`. Remediation is
    intentionally a separate layer with a human-in-the-loop policy gate
    because auto-remove here is how AV products brick customer machines.
"""

import os
import csv
import glob
import logging
import subprocess
from io import StringIO
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.response.persistence")


_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB — persistence files are small
_MIN_BASENAME_LEN = 6              # shorter names produce false positives
_SUBPROCESS_TIMEOUT = 30


# ---------- Indicator matching ----------

def _case_insensitive() -> bool:
    return os.name == "nt"


def _build_matchers(indicators: dict) -> list[tuple]:
    """Turn the indicator dict into (fn, label) pairs.

    Matchers are closures over their specific needle so label reporting
    remains unambiguous ("path:/tmp/evil" vs "basename:evil.bin").
    """
    ci = _case_insensitive()
    matchers: list[tuple] = []

    def add_path(p: str):
        if not p:
            return
        needle = p.lower() if ci else p
        matchers.append((
            lambda text, n=needle, c=ci:
                (n in text.lower()) if c else (n in text),
            f"path:{p}",
        ))

    def add_basename(b: str):
        if not b or len(b) < _MIN_BASENAME_LEN:
            return
        needle = b.lower() if ci else b
        matchers.append((
            lambda text, n=needle, c=ci:
                (n in text.lower()) if c else (n in text),
            f"basename:{b}",
        ))

    def add_hash(h: str):
        if not h or len(h) < 32:
            return
        needle = h.lower()
        matchers.append((
            lambda text, n=needle: n in text.lower(),
            f"hash:{h[:16]}",
        ))

    for p in indicators.get("paths", []) or []:
        add_path(p)
    for b in indicators.get("basenames", []) or []:
        add_basename(b)
    for h in indicators.get("hashes", []) or []:
        add_hash(h)
    return matchers


def _matches_any(text: str, matchers) -> Optional[str]:
    if not text:
        return None
    for fn, label in matchers:
        try:
            if fn(text):
                return label
        except Exception:
            continue
    return None


# ---------- File scanning primitives ----------

def _read_text_safe(path: Path) -> Optional[str]:
    try:
        st = path.stat()
        if st.st_size > _MAX_FILE_SIZE:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError, UnicodeDecodeError):
        return None


def _scan_file(path: Path, surface: str, matchers) -> list[dict]:
    text = _read_text_safe(path)
    if text is None:
        return []
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        label = _matches_any(line, matchers)
        if label:
            hits.append({
                "surface": surface,
                "location": str(path),
                "line": lineno,
                "reference": line.strip()[:400],
                "matched_indicator": label,
                "removable": False,
            })
    return hits


def _scan_glob_patterns(patterns, surface: str, matchers) -> list[dict]:
    hits = []
    seen: set[str] = set()
    for pattern in patterns:
        if not pattern:
            continue
        for p in glob.glob(pattern, recursive=True):
            if p in seen:
                continue
            seen.add(p)
            pth = Path(p)
            try:
                if not pth.is_file():
                    continue
            except OSError:
                continue
            hits.extend(_scan_file(pth, surface, matchers))
    return hits


# ---------- POSIX surfaces ----------

POSIX_CRON_PATTERNS = [
    "/etc/crontab",
    "/etc/cron.d/*",
    "/etc/cron.hourly/*",
    "/etc/cron.daily/*",
    "/etc/cron.weekly/*",
    "/etc/cron.monthly/*",
    "/var/spool/cron/crontabs/*",
    "/var/spool/cron/*",
]

POSIX_SYSTEMD_PATTERNS = [
    "/etc/systemd/system/*.service",
    "/etc/systemd/system/*.timer",
    "/etc/systemd/system/*/*.service",
    "/usr/lib/systemd/system/*.service",
    "/lib/systemd/system/*.service",
]

POSIX_PROFILE_PATTERNS = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/zsh/zshrc",
    "/etc/profile.d/*.sh",
]

POSIX_INIT_PATTERNS = [
    "/etc/rc.local",
    "/etc/init.d/*",
]

POSIX_LD_PATTERNS = [
    "/etc/ld.so.preload",
]


def _scan_cron(matchers, roots: Optional[dict] = None) -> list[dict]:
    patterns = (roots or {}).get("cron", POSIX_CRON_PATTERNS)
    hits = _scan_glob_patterns(patterns, "cron", matchers)
    # User crontab via `crontab -l`. Skipped if overrides supplied (tests).
    if roots is None:
        try:
            out = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True,
                timeout=_SUBPROCESS_TIMEOUT,
            )
            if out.returncode == 0 and out.stdout:
                for lineno, line in enumerate(out.stdout.splitlines(), 1):
                    label = _matches_any(line, matchers)
                    if label:
                        hits.append({
                            "surface": "cron",
                            "location": "user_crontab",
                            "line": lineno,
                            "reference": line.strip()[:400],
                            "matched_indicator": label,
                            "removable": False,
                        })
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
    return hits


def _scan_systemd(matchers, roots: Optional[dict] = None) -> list[dict]:
    patterns = (roots or {}).get("systemd", list(POSIX_SYSTEMD_PATTERNS))
    if roots is None:
        home = os.environ.get("HOME")
        if home:
            patterns = patterns + [
                os.path.join(home, ".config/systemd/user/*.service"),
                os.path.join(home, ".config/systemd/user/*.timer"),
            ]
    return _scan_glob_patterns(patterns, "systemd", matchers)


def _scan_profiles(matchers, roots: Optional[dict] = None) -> list[dict]:
    patterns = (roots or {}).get("profiles", list(POSIX_PROFILE_PATTERNS))
    if roots is None:
        home = os.environ.get("HOME")
        if home:
            patterns = patterns + [
                os.path.join(home, ".bashrc"),
                os.path.join(home, ".bash_profile"),
                os.path.join(home, ".profile"),
                os.path.join(home, ".zshrc"),
                os.path.join(home, ".zprofile"),
            ]
    return _scan_glob_patterns(patterns, "shell_profile", matchers)


def _scan_init(matchers, roots: Optional[dict] = None) -> list[dict]:
    patterns = (roots or {}).get("init", POSIX_INIT_PATTERNS)
    return _scan_glob_patterns(patterns, "init_script", matchers)


def _scan_ld_preload(matchers, roots: Optional[dict] = None) -> list[dict]:
    patterns = (roots or {}).get("ld_preload", POSIX_LD_PATTERNS)
    return _scan_glob_patterns(patterns, "ld_so_preload", matchers)


# ---------- Windows surfaces ----------

_WIN_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def _scan_registry_run(matchers, roots: Optional[dict] = None) -> list[dict]:
    """Enumerate Run/RunOnce values. `roots` can override with a file-based
    mock (list of dicts {label, values:{name: str_value}}) for tests — we
    don't want tests writing to the real HKLM."""
    if roots and "registry_mock" in roots:
        hits = []
        for entry in roots["registry_mock"]:
            label = entry.get("label", "MOCK\\Run")
            for name, value in (entry.get("values") or {}).items():
                m = _matches_any(str(value), matchers)
                if m:
                    hits.append({
                        "surface": "registry_run",
                        "location": f"{label}\\{name}",
                        "reference": str(value)[:400],
                        "matched_indicator": m,
                        "removable": False,
                    })
        return hits

    if os.name != "nt":
        return []
    try:
        import winreg
    except ImportError:
        return []

    hive_map = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
    }
    hits = []
    for hive_name, path in _WIN_RUN_KEYS:
        hive = hive_map[hive_name]
        try:
            key = winreg.OpenKey(hive, path)
        except FileNotFoundError:
            continue
        except OSError as e:
            logger.debug(f"Registry open failed {hive_name}\\{path}: {e}")
            continue
        try:
            i = 0
            while True:
                try:
                    name, value, _vtype = winreg.EnumValue(key, i)
                    i += 1
                except OSError:
                    break
                if isinstance(value, str):
                    m = _matches_any(value, matchers)
                    if m:
                        hits.append({
                            "surface": "registry_run",
                            "location": f"{hive_name}\\{path}\\{name}",
                            "reference": value[:400],
                            "matched_indicator": m,
                            "removable": False,
                        })
        finally:
            try:
                winreg.CloseKey(key)
            except Exception:
                pass
    return hits


def _scan_startup_folders(matchers, roots: Optional[dict] = None) -> list[dict]:
    if roots is not None and "startup_folders" in roots:
        patterns = roots["startup_folders"]
    else:
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("PROGRAMDATA", "")
        patterns = []
        if appdata:
            patterns.append(os.path.join(
                appdata, r"Microsoft\Windows\Start Menu\Programs\Startup\*"))
        if programdata:
            patterns.append(os.path.join(
                programdata, r"Microsoft\Windows\Start Menu\Programs\StartUp\*"))

    hits = []
    seen: set[str] = set()
    for pattern in patterns:
        if not pattern:
            continue
        for p in glob.glob(pattern):
            if p in seen:
                continue
            seen.add(p)
            pth = Path(p)
            try:
                if not pth.is_file():
                    continue
            except OSError:
                continue
            # Filename match — malware often drops an .exe directly here.
            m = _matches_any(pth.name, matchers)
            if m:
                hits.append({
                    "surface": "startup_folder",
                    "location": str(pth),
                    "reference": pth.name,
                    "matched_indicator": m,
                    "removable": False,
                })
            # Text-scan the ones we can read.
            if pth.suffix.lower() in {
                ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
            }:
                hits.extend(_scan_file(pth, "startup_folder", matchers))
    return hits


def _scan_scheduled_tasks(matchers, roots: Optional[dict] = None) -> list[dict]:
    """Enumerate scheduled tasks via `schtasks /query /fo CSV /v` and match
    the 'Task To Run' column. `roots['schtasks_csv']` lets tests inject a
    CSV fixture so we don't depend on the live task catalog."""
    csv_text: Optional[str] = None
    if roots is not None and "schtasks_csv" in roots:
        csv_text = roots["schtasks_csv"]
    elif os.name == "nt":
        try:
            out = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
            )
            if out.returncode == 0:
                csv_text = out.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []

    if not csv_text:
        return []

    hits = []
    try:
        reader = csv.reader(StringIO(csv_text))
        header: Optional[list[str]] = None
        task_idx: Optional[int] = None
        name_idx: Optional[int] = None
        for row in reader:
            if not row:
                continue
            first = row[0].strip().strip('"')
            if header is None or first == "HostName":
                # schtasks CSV repeats the header per task group — re-read.
                header = [c.strip().strip('"') for c in row]
                task_idx = (header.index("Task To Run")
                            if "Task To Run" in header else None)
                name_idx = (header.index("TaskName")
                            if "TaskName" in header else None)
                continue
            if task_idx is None or len(row) <= task_idx:
                continue
            command = row[task_idx].strip().strip('"')
            m = _matches_any(command, matchers)
            if m:
                task_name = "?"
                if name_idx is not None and len(row) > name_idx:
                    task_name = row[name_idx].strip().strip('"')
                hits.append({
                    "surface": "scheduled_task",
                    "location": task_name,
                    "reference": command[:400],
                    "matched_indicator": m,
                    "removable": False,
                })
    except Exception as e:
        logger.debug(f"schtasks CSV parse error: {e}")
    return hits


# ---------- Orchestrator ----------

def hunt_persistence(
    indicators: dict,
    *,
    roots: Optional[dict] = None,
    platform: Optional[str] = None,
) -> dict:
    """Run every persistence surface scanner and collect hits.

    Args:
        indicators: {"paths": [...], "basenames": [...], "hashes": [...]}.
        roots: optional per-surface override for test fixtures. Keys:
            "cron", "systemd", "profiles", "init", "ld_preload",
            "startup_folders", "registry_mock", "schtasks_csv".
        platform: "nt" or "posix" to force a platform scan regardless of
            the host. Useful for testing Windows surfaces on POSIX by
            injecting registry_mock / schtasks_csv.

    Returns:
        {
          "hits": [...],
          "surfaces_scanned": [...],
          "surfaces_failed": [{"surface": ..., "error": ...}],
          "indicator_count": int,
        }
    """
    matchers = _build_matchers(indicators)
    if not matchers:
        return {
            "hits": [],
            "surfaces_scanned": [],
            "surfaces_failed": [],
            "indicator_count": 0,
        }

    plat = platform or ("nt" if os.name == "nt" else "posix")

    if plat == "nt":
        surface_fns = [
            ("registry_run", lambda: _scan_registry_run(matchers, roots)),
            ("startup_folders", lambda: _scan_startup_folders(matchers, roots)),
            ("scheduled_tasks", lambda: _scan_scheduled_tasks(matchers, roots)),
        ]
    else:
        surface_fns = [
            ("cron", lambda: _scan_cron(matchers, roots)),
            ("systemd", lambda: _scan_systemd(matchers, roots)),
            ("shell_profile", lambda: _scan_profiles(matchers, roots)),
            ("init_script", lambda: _scan_init(matchers, roots)),
            ("ld_so_preload", lambda: _scan_ld_preload(matchers, roots)),
        ]

    all_hits: list[dict] = []
    scanned: list[str] = []
    failed: list[dict] = []

    for name, fn in surface_fns:
        try:
            all_hits.extend(fn())
            scanned.append(name)
        except Exception as e:
            logger.warning(f"Persistence surface {name} failed: {e}",
                           exc_info=True)
            failed.append({"surface": name, "error": str(e)})

    return {
        "hits": all_hits,
        "surfaces_scanned": scanned,
        "surfaces_failed": failed,
        "indicator_count": len(matchers),
    }


def build_indicators_from_quarantine(primary: dict,
                                     siblings: list[dict]) -> dict:
    """Assemble a single indicator dict from primary + sibling quarantine
    records. We include both the original path AND the quarantine_path so
    a persistence mechanism pointing at either surface is found."""
    paths: list[str] = []
    basenames: list[str] = []
    hashes: list[str] = []

    for rec in [primary] + list(siblings or []):
        if not rec:
            continue
        orig = rec.get("original_path")
        if orig:
            paths.append(orig)
            basenames.append(os.path.basename(orig))
        qpath = rec.get("quarantine_path")
        if qpath:
            paths.append(qpath)
        h = rec.get("sha256")
        if h:
            hashes.append(h)

    # De-dup while preserving order.
    def uniq(xs):
        seen = set()
        out = []
        for x in xs:
            if x and x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "paths": uniq(paths),
        "basenames": uniq(basenames),
        "hashes": uniq(hashes),
    }
