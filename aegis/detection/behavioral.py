"""
AEGIS Behavioral Detection Engine
====================================
Evaluates process and file events against behavioral detection rules.
Rules detect attack patterns (reverse shells, privesc, persistence, etc.)
rather than static signatures.

Each rule maps to a MITRE ATT&CK technique for standardized reporting.

Inspired by: Sigma rules, Elastic Detection Rules, CrowdStrike IOAs
"""

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.detection.behavioral")


@dataclass
class BehavioralRule:
    """A single behavioral detection rule."""
    rule_id: str
    name: str
    description: str
    severity: Severity
    mitre_attack: str
    # Conditions — at least one must match
    cmdline_patterns: list[str] = field(default_factory=list)  # regex patterns
    file_patterns: list[str] = field(default_factory=list)
    env_patterns: dict = field(default_factory=dict)           # env var → value pattern
    # Process ancestry conditions
    parent_name_patterns: list[str] = field(default_factory=list)
    # Temporal correlation
    requires_sequence: list[str] = field(default_factory=list)  # ordered event patterns
    sequence_window_seconds: float = 10.0
    enabled: bool = True


# ═══════════════════════════════════════════════════════════
# DETECTION RULES — AEGIS Rule Set v1
# Mapped to MITRE ATT&CK Framework
# ═══════════════════════════════════════════════════════════

RULES: list[BehavioralRule] = [

    # ── Execution ──────────────────────────────────────────
    BehavioralRule(
        rule_id="AEG-001",
        name="Reverse Shell",
        description="Detects reverse shell command patterns",
        severity=Severity.CRITICAL,
        mitre_attack="T1059.004",
        cmdline_patterns=[
            r"bash\s+-i\s+>&\s+/dev/tcp",
            r"nc\s+(-e|--exec)\s+/bin/(sh|bash)",
            r"ncat\s+(-e|--exec)\s+/bin/(sh|bash)",
            r"socat\s+.*exec.*",
            r"python[23]?\s+-c\s+.*socket.*connect",
            r"perl\s+-e\s+.*socket.*",
            r"ruby\s+-rsocket\s+-e",
            r"php\s+-r\s+.*fsockopen",
            r"mkfifo\s+/tmp/.*\s*;\s*cat\s+/tmp/",
            r"0<&\d+;exec\s+\d+<>/dev/tcp",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-002",
        name="SUID/SGID Exploitation",
        description="Process spawned via SUID binary with escalated privileges",
        severity=Severity.CRITICAL,
        mitre_attack="T1548.001",
        cmdline_patterns=[
            r"find\s+/\s+-perm\s+-4000",        # Searching for SUID
            r"find\s+.*-exec\s+/bin/(sh|bash)",   # SUID find abuse
            r"pkexec\s+",
            r"python[23]?\s+.*import\s+os.*setuid",
        ],
    ),

    # ── Persistence ────────────────────────────────────────
    BehavioralRule(
        rule_id="AEG-004",
        name="Cron Persistence",
        description="Crontab modification for persistence",
        severity=Severity.HIGH,
        mitre_attack="T1053.003",
        cmdline_patterns=[
            r"crontab\s+-[el]",
            r"echo\s+.*>>\s*/etc/cron",
            r"echo\s+.*>>\s*/var/spool/cron",
        ],
        file_patterns=[
            r"/etc/cron\.",
            r"/var/spool/cron/",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-005",
        name="Shell Profile Backdoor",
        description="Modification of shell startup files for persistence",
        severity=Severity.HIGH,
        mitre_attack="T1546.004",
        file_patterns=[
            r"\.bashrc$",
            r"\.bash_profile$",
            r"\.profile$",
            r"/etc/profile\.d/",
            r"\.zshrc$",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-013",
        name="Systemd Service Persistence",
        description="Creation of systemd service unit for persistence",
        severity=Severity.HIGH,
        mitre_attack="T1543.002",
        cmdline_patterns=[
            r"systemctl\s+enable\s+",
            r"systemctl\s+daemon-reload",
        ],
        file_patterns=[
            r"/etc/systemd/system/.*\.service$",
            r"/lib/systemd/system/.*\.service$",
            r"\.timer$",
        ],
    ),

    # ── Defense Evasion ────────────────────────────────────
    BehavioralRule(
        rule_id="AEG-008",
        name="LD_PRELOAD Hijacking",
        description="Dynamic linker hijacking via LD_PRELOAD",
        severity=Severity.CRITICAL,
        mitre_attack="T1574.006",
        cmdline_patterns=[
            r"LD_PRELOAD=",
        ],
        env_patterns={"LD_PRELOAD": r".+"},
        file_patterns=[
            r"/etc/ld\.so\.preload",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-009",
        name="Encoded Command Execution",
        description="Obfuscated command using base64 or eval",
        severity=Severity.MEDIUM,
        mitre_attack="T1059",
        cmdline_patterns=[
            r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d",
            r"base64\s+(-d|--decode)\s*\|",
            r"python[23]?\s+-c\s+.*__import__.*exec",
            r"perl\s+-e\s+.*eval\s*\(",
            r"ruby\s+-e\s+.*eval\s*\(",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-014",
        name="History Deletion",
        description="Attempts to clear command history (anti-forensics)",
        severity=Severity.MEDIUM,
        mitre_attack="T1070.003",
        cmdline_patterns=[
            r"history\s+-c",
            r"unset\s+HISTFILE",
            r"export\s+HISTFILESIZE=0",
            r"rm\s+.*\.bash_history",
            r"truncate.*\.bash_history",
            r"shred.*\.bash_history",
        ],
    ),

    # ── Discovery ──────────────────────────────────────────
    BehavioralRule(
        rule_id="AEG-015",
        name="System Enumeration",
        description="Aggressive system reconnaissance",
        severity=Severity.LOW,
        mitre_attack="T1082",
        cmdline_patterns=[
            r"uname\s+-a",
            r"cat\s+/etc/(passwd|shadow|hosts)",
            r"cat\s+/proc/version",
            r"whoami\s*&&\s*id\s*&&\s*hostname",
            r"ifconfig\s*&&\s*netstat",
            r"ip\s+addr\s*&&\s*ss\s+-tlnp",
        ],
    ),

    # ── Lateral Movement ────────────────────────────────────
    BehavioralRule(
        rule_id="AEG-016",
        name="SSH Key Theft or Planting",
        description="Accessing or modifying SSH keys",
        severity=Severity.HIGH,
        mitre_attack="T1563.001",
        cmdline_patterns=[
            r"cat\s+.*\.ssh/(id_rsa|authorized_keys)",
            r"cp\s+.*\.ssh/",
            r"echo\s+.*>>\s*.*\.ssh/authorized_keys",
        ],
        file_patterns=[
            r"\.ssh/authorized_keys$",
            r"\.ssh/id_rsa$",
        ],
    ),

    # ── Resource Hijacking ─────────────────────────────────
    BehavioralRule(
        rule_id="AEG-006",
        name="Cryptominer Execution",
        description="Cryptocurrency mining software detected",
        severity=Severity.HIGH,
        mitre_attack="T1496",
        cmdline_patterns=[
            r"xmrig",
            r"stratum\+tcp://",
            r"stratum\+ssl://",
            r"minerd",
            r"cpuminer",
            r"--coin\s+",
            r"pool\..*\.(com|net|org)",
        ],
    ),

    # ── Command & Control ──────────────────────────────────
    BehavioralRule(
        rule_id="AEG-003",
        name="Download and Execute",
        description="Downloading and immediately executing code",
        severity=Severity.HIGH,
        mitre_attack="T1105",
        cmdline_patterns=[
            r"curl\s+.*\|\s*(sh|bash|python|perl|ruby)",
            r"wget\s+.*-O\s*-\s*\|\s*(sh|bash)",
            r"curl\s+.*-o\s+/tmp/.*;\s*chmod\s+\+x",
            r"wget\s+.*;\s*chmod\s+\+x",
            r"python[23]?\s+-c\s+.*urllib.*exec",
        ],
    ),

    # ── Collection ─────────────────────────────────────────
    BehavioralRule(
        rule_id="AEG-017",
        name="Data Staging for Exfiltration",
        description="Compressing or staging data for exfil",
        severity=Severity.MEDIUM,
        mitre_attack="T1074.001",
        cmdline_patterns=[
            r"tar\s+.*czf\s+/tmp/",
            r"zip\s+.*-r\s+/tmp/",
            r"7z\s+a\s+/tmp/",
        ],
    ),

    # ── Impact ─────────────────────────────────────────────
    BehavioralRule(
        rule_id="AEG-018",
        name="Data Destruction",
        description="Mass file deletion or disk wiping",
        severity=Severity.CRITICAL,
        mitre_attack="T1485",
        cmdline_patterns=[
            r"rm\s+-rf\s+/",
            r"dd\s+if=/dev/(zero|urandom)\s+of=/dev/sd",
            r"shred\s+.*-[fuz]",
            r"mkfs\s+",
        ],
    ),

    # ── Container Escape ───────────────────────────────────
    BehavioralRule(
        rule_id="AEG-012",
        name="Container Escape Attempt",
        description="Attempting to escape container isolation",
        severity=Severity.CRITICAL,
        mitre_attack="T1611",
        cmdline_patterns=[
            r"nsenter\s+",
            r"mount\s+.*proc",
            r"/proc/sysrq-trigger",
            r"docker\.sock",
            r"cgroup.*release_agent",
            r"capsh\s+--print",
            r"unshare\s+",
        ],
    ),

    # ── Windows LOLBin Abuse ──────────────────────────────
    BehavioralRule(
        rule_id="AEG-019",
        name="Certutil Download",
        description="Certutil used to download remote payload",
        severity=Severity.HIGH,
        mitre_attack="T1105",
        cmdline_patterns=[
            r"certutil\.exe.*(-urlcache|-split|-f).*http",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-020",
        name="MSHTA Execution",
        description="MSHTA executing remote or inline script",
        severity=Severity.CRITICAL,
        mitre_attack="T1218.005",
        cmdline_patterns=[
            r"mshta\.exe.*(http|javascript|vbscript)",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-021",
        name="Regsvr32 Proxy Execution",
        description="Regsvr32 used to proxy execute remote scriptlet",
        severity=Severity.CRITICAL,
        mitre_attack="T1218.010",
        cmdline_patterns=[
            r"regsvr32\.exe.*/s.*/i.*http",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-022",
        name="Rundll32 Abuse",
        description="Rundll32 executing JavaScript or suspicious shell function",
        severity=Severity.HIGH,
        mitre_attack="T1218.011",
        cmdline_patterns=[
            r"rundll32\.exe.*javascript",
            r"rundll32\.exe.*shell32",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-023",
        name="BITSAdmin Download",
        description="BITSAdmin used to download remote payload",
        severity=Severity.HIGH,
        mitre_attack="T1197",
        cmdline_patterns=[
            r"bitsadmin.*/transfer.*http",
        ],
    ),

    BehavioralRule(
        rule_id="AEG-024",
        name="PowerShell Encoded Command",
        description="PowerShell executing base64-encoded command",
        severity=Severity.HIGH,
        mitre_attack="T1059.001",
        cmdline_patterns=[
            r"powershell.*-[eE]n[cC].*[A-Za-z0-9+/=]{20,}",
        ],
    ),
]


class BehavioralEngine:
    """
    Evaluates process events against behavioral detection rules.
    Subscribes to PROC_CREATE events from the process monitor.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self.rules = [r for r in RULES if r.enabled]
        self._running = False
        self._detection_count = 0
        self._eval_count = 0

        # Compiled regex cache
        self._compiled: dict[str, list[re.Pattern]] = {}
        for rule in self.rules:
            self._compiled[rule.rule_id] = [
                re.compile(p, re.IGNORECASE) for p in rule.cmdline_patterns
            ]

    def start(self):
        """Subscribe to process creation events."""
        self.bus.subscribe(EventCategory.PROC_CREATE.value, self._on_process)
        self.bus.subscribe(EventCategory.PROC_SUSPICIOUS.value, self._on_process)
        self.bus.subscribe(EventCategory.FILE_CREATE.value, self._on_file)
        self.bus.subscribe(EventCategory.FILE_MODIFY.value, self._on_file)
        self._running = True
        logger.info(f"Behavioral engine started. {len(self.rules)} rules loaded.")

    def _on_process(self, event: Event):
        """Evaluate a process creation event against all rules."""
        cmdline = event.data.get("cmdline", "")
        if not cmdline:
            return

        self._eval_count += 1

        for rule in self.rules:
            if self._matches_cmdline(rule, cmdline):
                self._fire_detection(rule, event, "cmdline", cmdline)
            # Check environment variables
            if rule.env_patterns:
                environ = event.data.get("environ", {})
                if not isinstance(environ, dict):
                    continue
                for env_var, pattern in rule.env_patterns.items():
                    val = environ.get(env_var, "")
                    if val and re.search(pattern, val, re.IGNORECASE):
                        self._fire_detection(rule, event, "environ",
                                             f"{env_var}={val}")

    def _on_file(self, event: Event):
        """Evaluate file events against file-based rules."""
        filepath = event.data.get("path", "")
        if not filepath:
            return

        for rule in self.rules:
            if rule.file_patterns:
                for pattern in rule.file_patterns:
                    if re.search(pattern, filepath, re.IGNORECASE):
                        self._fire_detection(rule, event, "file_path", filepath)
                        break

    def _matches_cmdline(self, rule: BehavioralRule, cmdline: str) -> bool:
        """Check if cmdline matches any of the rule's patterns."""
        patterns = self._compiled.get(rule.rule_id, [])
        return any(p.search(cmdline) for p in patterns)

    def _fire_detection(self, rule: BehavioralRule, source_event: Event,
                        match_type: str, match_value: str):
        """Publish a detection event."""
        self._detection_count += 1

        self.bus.publish(Event(
            category=EventCategory.DETECTION_BEHAVIORAL,
            severity=rule.severity,
            source="behavioral",
            mitre_attack=rule.mitre_attack,
            data={
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "description": rule.description,
                "match_type": match_type,
                "match_value": match_value[:500],
                "source_event": source_event.data,
                "pid": source_event.data.get("pid", 0),
                "process": source_event.data.get("name", ""),
            },
        ))
        logger.warning(f"BEHAVIORAL DETECTION: [{rule.rule_id}] {rule.name} — "
                       f"{match_type}='{match_value[:80]}'")

    @property
    def stats(self) -> dict:
        return {
            "rules_loaded": len(self.rules),
            "evaluations": self._eval_count,
            "detections": self._detection_count,
            "running": self._running,
        }

    @property
    def is_running(self) -> bool:
        return self._running
