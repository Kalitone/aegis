"""
AEGIS YARA Scanner
====================
Integrates the YARA pattern matching engine with the FIM event stream.
When a file is created or modified, it's automatically scanned against loaded rules.

Rule sources (loaded in priority order):
  1. Custom rules in rules/yara/custom/
  2. Community rules (signature-base, YARA-Rules)
  3. Auto-generated rules from behavioral analysis

Inspired by: ClamAV signature engine, YARA-CI, Loki scanner
"""

import os
import time
import logging
import threading
from pathlib import Path
from typing import Optional

try:
    import yara
except ImportError:
    yara = None

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.detection.yara_scanner")


# Built-in YARA rules for common threats when no external rules are loaded
BUILTIN_RULES = """
rule suspicious_elf_dropper {
    meta:
        description = "Detects suspicious ELF with network and exec capabilities"
        severity = "high"
        mitre = "T1059"
    strings:
        $elf = { 7F 45 4C 46 }
        $s1 = "/bin/sh" ascii
        $s2 = "/bin/bash" ascii
        $s3 = "socket" ascii
        $s4 = "connect" ascii
        $s5 = "execve" ascii
    condition:
        $elf at 0 and 2 of ($s1, $s2) and 2 of ($s3, $s4, $s5)
}

rule suspicious_script_downloader {
    meta:
        description = "Script that downloads and executes code"
        severity = "high"
        mitre = "T1105"
    strings:
        $d1 = "curl " ascii nocase
        $d2 = "wget " ascii nocase
        $d3 = "Invoke-WebRequest" ascii nocase
        $d4 = "urllib" ascii nocase
        $d5 = "requests.get" ascii nocase
        $e1 = "| sh" ascii
        $e2 = "| bash" ascii
        $e3 = "exec(" ascii
        $e4 = "eval(" ascii
        $e5 = "subprocess" ascii
        $e6 = "os.system" ascii
    condition:
        any of ($d*) and any of ($e*)
}

rule cryptominer_strings {
    meta:
        description = "Cryptocurrency miner indicators"
        severity = "high"
        mitre = "T1496"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "xmrig" ascii nocase
        $s4 = "cpuminer" ascii nocase
        $s5 = "minerd" ascii nocase
        $s6 = "hashrate" ascii nocase
        $s7 = "mining.notify" ascii
        $s8 = "coin-hive" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
    // Original condition (kept for reference, replaced below):
    //     2 of ($s*) or $wallet
    condition: false and any of them  // DISABLED 2026-04-24: see analysis_reports/01_security.md - produced 100% FP rate; broke condition fires on plain English text. Re-enable only after adding PE/ELF magic gating and removing single-token strings. (`false and any of them` keeps all string defs referenced so yara-python compiles cleanly while still never matching.)
}

rule reverse_shell_script {
    meta:
        description = "Reverse shell in script file"
        severity = "critical"
        mitre = "T1059.004"
    strings:
        $r1 = "/dev/tcp/" ascii
        $r2 = "nc -e /bin" ascii
        $r3 = "ncat -e /bin" ascii
        $r4 = "bash -i >& /dev" ascii
        $r5 = "mkfifo /tmp" ascii
        $r6 = "socat exec" ascii nocase
        $py1 = "socket.socket" ascii
        $py2 = ".connect((" ascii
        $py3 = "subprocess.call" ascii
    condition:
        any of ($r*) or (2 of ($py*))
}

rule webshell_generic {
    meta:
        description = "Generic web shell patterns"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $php1 = "eval($_" ascii
        $php2 = "base64_decode($_" ascii
        $php3 = "system($_" ascii
        $php4 = "passthru(" ascii
        $php5 = "shell_exec(" ascii
        $asp1 = "eval(Request" ascii nocase
        $asp2 = "Execute(Request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii
    condition:
        any of them
}

rule suspicious_packed_binary {
    meta:
        description = "Potentially packed/encrypted binary"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $upx = "UPX!" ascii
        $mpress = "MPRESS" ascii
        $nsp = ".nsp0" ascii
        $aspack = "aPLib" ascii
    condition:
        any of them
}

rule credential_access_file {
    meta:
        description = "File accessing credential stores"
        severity = "high"
        mitre = "T1003"
    strings:
        $s1 = "/etc/shadow" ascii
        $s2 = "SAM database" ascii nocase
        $s3 = "mimikatz" ascii nocase
        $s4 = "sekurlsa" ascii nocase
        $s5 = "lsass.exe" ascii nocase
        $s6 = "credential" ascii nocase
        $s7 = "password" ascii nocase
        $s8 = "hashdump" ascii nocase
    // Original condition (kept for reference, replaced below):
    //     3 of them
    condition: false and any of them  // DISABLED 2026-04-24: see analysis_reports/01_security.md - produced 100% FP rate; broke condition fires on plain English text. Re-enable only after adding PE/ELF magic gating and removing single-token strings. (`false and any of them` keeps all string defs referenced so yara-python compiles cleanly while still never matching.)
}

rule persistence_mechanism {
    meta:
        description = "File containing persistence installation code"
        severity = "high"
        mitre = "T1053"
    strings:
        $c1 = "crontab -" ascii
        $c2 = "/etc/cron" ascii
        $s1 = "systemctl enable" ascii
        $s2 = "/etc/systemd" ascii
        $s3 = "/etc/init.d/" ascii
        $b1 = ".bashrc" ascii
        $b2 = ".bash_profile" ascii
        $b3 = "/etc/profile.d/" ascii
        $w1 = "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii nocase
        $w2 = "schtasks /create" ascii nocase
    condition:
        2 of them
}
"""


# Paths where YARA string-based rules are almost guaranteed to false-positive.
# These are text/database/cache stores — NOT places where executable payloads live.
# Substrings are matched case-insensitively against the normalized (forward-slash) path.
DEFAULT_EXCLUDE_SUBSTRINGS: tuple[str, ...] = (
    # Browser caches and profile databases
    "/appdata/local/google/chrome/",
    "/appdata/local/microsoft/edge/",
    "/appdata/roaming/mozilla/firefox/",
    "/appdata/local/brave/",
    "/appdata/local/opera software/",
    "/appdata/local/vivaldi/",
    # Windows notifications / settings / package state
    "/appdata/local/microsoft/windows/notifications/",
    "/appdata/local/packages/",
    "/appdata/local/microsoft/onedrive/",
    # Windows event logs
    "/windows/system32/winevt/",
    # IDE / Electron app workspace state
    "/appdata/roaming/code/",
    "/appdata/roaming/cursor/",
    "/appdata/roaming/antigravity/",
    "/.vscode/",
    "/globalstorage/",
    # Torrent app state
    "/appdata/roaming/bittorrent web/",
    # Claude's own conversation transcripts (contain security strings as text)
    "/.claude/projects/",
    # AEGIS itself — scanning our own rules/logs is guaranteed false positive
    "/aegis/rules/",
    "/aegis/logs/",
    "/aegis/data/",
)

# File extensions that are data/logs/databases, not executables — skip these
# for YARA string rules regardless of path.
DEFAULT_EXCLUDE_EXTS: frozenset[str] = frozenset({
    ".log", ".evtx", ".etl", ".wal", ".db", ".db-wal", ".db-shm",
    ".sqlite", ".sqlite-wal", ".sqlite-shm", ".vscdb", ".vscdb-journal",
    ".dat", ".blob", ".ldb", ".leveldb",
})


class YaraScanner:
    """
    YARA-based file scanner integrated with the AEGIS event bus.
    Subscribes to FILE_CREATE and FILE_MODIFY events for on-access scanning.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self._rules = None
        self._rules_dir = config.get("rules_dir", "rules/yara")
        self._max_file_size = config.get("max_file_size_mb", 100) * 1024 * 1024
        self._scan_timeout = config.get("scan_timeout_seconds", 30)
        # Exclusions: user-supplied list extends the defaults.
        user_excludes = tuple(
            s.lower().replace("\\", "/") for s in config.get("exclude_paths", [])
        )
        self._exclude_substrings = DEFAULT_EXCLUDE_SUBSTRINGS + user_excludes
        user_exts = {e.lower() for e in config.get("exclude_extensions", [])}
        self._exclude_exts = DEFAULT_EXCLUDE_EXTS | user_exts
        self._skipped_count = 0
        self._running = False
        self._scan_count = 0
        self._detection_count = 0

    def _is_excluded(self, filepath: str) -> bool:
        norm = filepath.replace("\\", "/").lower()
        if any(sub in norm for sub in self._exclude_substrings):
            return True
        # match extension (handle double-ext like .db-wal)
        base = norm.rsplit("/", 1)[-1]
        if "." in base:
            # try full tail after first dot too, for .db-wal / .sqlite-shm
            parts = base.split(".")
            for i in range(1, len(parts)):
                ext = "." + ".".join(parts[i:])
                if ext in self._exclude_exts:
                    return True
        return False

    def start(self):
        """Load rules and subscribe to file events."""
        if yara is None:
            logger.error("yara-python not installed. YARA scanner disabled.")
            return

        self._load_rules()

        # Subscribe to file creation and modification events
        self.bus.subscribe(EventCategory.FILE_CREATE.value, self._on_file_event)
        self.bus.subscribe(EventCategory.FILE_MODIFY.value, self._on_file_event)

        self._running = True
        logger.info(f"YARA scanner started. Rules loaded. Listening for file events.")

        self.bus.publish(Event(
            category=EventCategory.SYSTEM_START,
            severity=Severity.INFO,
            source="yara",
            data={"status": "started", "rules_loaded": True},
        ))

    def _load_rules(self):
        """Load YARA rules from files and built-in rules."""
        sources = {}

        # Load built-in rules
        sources["builtin"] = BUILTIN_RULES

        # Load rules from rules directory
        rules_path = Path(self._rules_dir)
        if rules_path.exists():
            for rule_file in rules_path.rglob("*.yar"):
                try:
                    sources[str(rule_file)] = rule_file.read_text()
                    logger.info(f"Loaded YARA rules: {rule_file}")
                except Exception as e:
                    logger.error(f"Failed to load YARA rule {rule_file}: {e}")

            for rule_file in rules_path.rglob("*.yara"):
                try:
                    sources[str(rule_file)] = rule_file.read_text()
                    logger.info(f"Loaded YARA rules: {rule_file}")
                except Exception as e:
                    logger.error(f"Failed to load YARA rule {rule_file}: {e}")

        try:
            self._rules = yara.compile(sources=sources)
            logger.info(f"YARA rules compiled successfully ({len(sources)} sources)")
        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
            # Fall back to just built-in rules
            try:
                self._rules = yara.compile(source=BUILTIN_RULES)
                logger.info("Fell back to built-in rules only")
            except Exception as e2:
                logger.error(f"Failed to compile even built-in rules: {e2}")

    def _on_file_event(self, event: Event):
        """Handle file creation/modification events from FIM."""
        filepath = event.data.get("path", "")
        if not filepath or not os.path.isfile(filepath):
            return

        # Skip known false-positive sources (browser caches, DBs, event logs,
        # IDE workspace state, our own logs).
        if self._is_excluded(filepath):
            self._skipped_count += 1
            return

        # Skip very large files
        try:
            size = os.path.getsize(filepath)
            if size > self._max_file_size:
                return
            if size == 0:
                return
        except OSError:
            return

        # Scan in background to avoid blocking the event bus
        thread = threading.Thread(
            target=self._scan_file,
            args=(filepath, event.data.get("hash", "")),
            daemon=True,
        )
        thread.start()

    @staticmethod
    def _format_strings(strings) -> list[dict]:
        """Format YARA string matches across different yara-python versions."""
        result = []
        for s in strings:
            try:
                # yara-python >= 4.3: StringMatch objects
                if hasattr(s, 'identifier'):
                    ident = s.identifier
                    instances = list(s.instances) if hasattr(s, 'instances') else []
                    for inst in instances[:3]:
                        offset = inst.offset if hasattr(inst, 'offset') else 0
                        data = inst.matched_data if hasattr(inst, 'matched_data') else b''
                        result.append({
                            "identifier": ident,
                            "offset": offset,
                            "data": data[:50].hex() if isinstance(data, bytes) else str(data)[:50],
                        })
                    if not instances:
                        result.append({"identifier": ident, "offset": 0, "data": ""})
                # yara-python < 4.3: tuple (offset, identifier, data)
                elif isinstance(s, tuple) and len(s) >= 3:
                    result.append({
                        "offset": s[0],
                        "identifier": s[1],
                        "data": s[2][:50].hex() if isinstance(s[2], bytes) else str(s[2])[:50],
                    })
            except Exception:
                result.append({"identifier": str(s), "offset": 0, "data": ""})
        return result

    def _scan_file(self, filepath: str, file_hash: str):
        """Scan a single file with YARA rules."""
        if not self._rules:
            return

        self._scan_count += 1
        try:
            matches = self._rules.match(filepath, timeout=self._scan_timeout)
            if matches:
                self._detection_count += 1
                for match in matches:
                    meta = match.meta
                    severity_str = meta.get("severity", "medium")
                    severity_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                    }
                    severity = severity_map.get(severity_str, Severity.MEDIUM)
                    mitre = meta.get("mitre", "")

                    self.bus.publish(Event(
                        category=EventCategory.DETECTION_YARA,
                        severity=severity,
                        source="yara",
                        mitre_attack=mitre,
                        data={
                            "rule": match.rule,
                            "description": meta.get("description", ""),
                            "filepath": filepath,
                            "file_hash": file_hash,
                            "tags": list(match.tags),
                            "strings": self._format_strings(match.strings[:10]),
                        },
                    ))
                    logger.warning(f"YARA DETECTION: rule={match.rule} file={filepath}")

        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout on {filepath}")
        except yara.Error as e:
            logger.error(f"YARA scan error on {filepath}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error scanning {filepath}: {e}")

    def scan_processes(self, max_pids: int = 0) -> list[dict]:
        """
        Scan running process memory with the loaded YARA rules. Catches
        fileless / packed malware (Cobalt Strike beacons, in-memory droppers,
        process-hollowed payloads) that on-disk file scanning misses.

        On Windows we need PROCESS_VM_READ + PROCESS_QUERY_INFORMATION, which
        means we must run as SYSTEM (the NSSM service does). On Linux we read
        /proc/<pid>/mem; non-root callers will silently skip processes they
        can't open. Either way: no exception, no blocking — best-effort.

        max_pids=0 means scan all; pass a small number for periodic sampling.
        """
        detections: list[dict] = []
        if not self._rules:
            return detections
        try:
            import psutil
        except ImportError:
            return detections

        scanned = 0
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            if max_pids and scanned >= max_pids:
                break
            pid = proc.info["pid"]
            if pid <= 4:                     # System / Idle / kernel
                continue
            try:
                matches = self._rules.match(pid=pid, timeout=self._scan_timeout)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                # yara raises a generic Error on permission issues — swallow.
                logger.debug(f"yara mem-scan pid={pid}: {e}")
                continue
            scanned += 1
            for match in matches:
                meta = match.meta or {}
                sev = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW
                      }.get(str(meta.get("severity", "high")), Severity.HIGH)
                self.bus.publish(Event(
                    category=EventCategory.DETECTION_YARA,
                    severity=sev,
                    source="yara.memory",
                    mitre_attack=meta.get("mitre", "T1055"),  # Process Injection bucket
                    data={
                        "rule": match.rule,
                        "rule_name": match.rule,
                        "description": meta.get("description",
                                                "in-memory YARA hit"),
                        "pid": pid,
                        "process": proc.info.get("name", ""),
                        "exe": proc.info.get("exe", ""),
                        "tags": list(match.tags),
                        "scan_target": "process_memory",
                    },
                ))
                detections.append({"pid": pid, "rule": match.rule,
                                   "process": proc.info.get("name", "")})
                logger.warning(f"YARA MEMORY DETECTION: pid={pid} "
                               f"name={proc.info.get('name', '')} rule={match.rule}")
        logger.info(f"YARA memory scan complete: {scanned} processes scanned, "
                    f"{len(detections)} detection(s)")
        return detections

    def start_memory_scan_loop(self, interval_seconds: float = 600.0,
                               max_pids: int = 0):
        """Periodic background memory scan. Default: every 10 minutes."""
        def _loop():
            while self._running:
                try:
                    self.scan_processes(max_pids=max_pids)
                except Exception as e:
                    logger.error(f"memory scan loop error: {e}")
                slept = 0.0
                while self._running and slept < interval_seconds:
                    time.sleep(2.0)
                    slept += 2.0
        t = threading.Thread(target=_loop, daemon=True, name="aegis-yara-mem")
        t.start()
        logger.info(f"YARA memory scan loop started (every {interval_seconds}s)")

    def scan_directory(self, path: str) -> list[dict]:
        """Manually scan an entire directory. Returns list of detections."""
        detections = []
        if not self._rules:
            return detections

        for root, dirs, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    matches = self._rules.match(fpath, timeout=self._scan_timeout)
                    for match in matches:
                        detections.append({
                            "rule": match.rule,
                            "file": fpath,
                            "meta": match.meta,
                        })
                except Exception:
                    continue
        return detections

    @property
    def stats(self) -> dict:
        return {
            "scans": self._scan_count,
            "detections": self._detection_count,
            "running": self._running,
        }

    @property
    def is_running(self) -> bool:
        return self._running
