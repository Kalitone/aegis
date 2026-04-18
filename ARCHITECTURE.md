# AEGIS Architecture Document

## Adaptive Endpoint Guardian Intelligence System

> This document fully describes the AEGIS architecture — every layer, component, data flow,
> design decision, and interface. Any developer, model, or agent should be able to understand
> the system and extend it from this document alone.

---

## 1. System Overview

AEGIS is a layered, modular endpoint security system built in Python. It provides defense-in-depth
through five layers: hardening, monitoring, detection, correlation, and response. It is designed
to run on a single host (Phase A), scale to a small network (Phase B), and ultimately protect
a fleet (Phase C).

### Design Principles

1. **Defense in depth:** Every layer can fail independently. A threat must evade ALL layers.
2. **Hybrid architecture:** Thin interception (monitors) + heavy analysis (detection engines).
   Mirrors how production AV/EDR systems are built.
3. **Cross-platform:** Uses psutil and watchdog for Windows/Linux/macOS support. No kernel
   module dependencies.
4. **Event-driven:** All components communicate via a central event bus. Loose coupling allows
   independent development, testing, and replacement of any component.
5. **Observable:** Every action is logged, persisted, and queryable. Forensic data is captured
   before any destructive response action.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     AEGIS ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  LAYER 4: RESPONSE ENGINE                               │   │
│  │  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌─────────┐  │   │
│  │  │Kill Proc │ │Quarantine  │ │Forensic  │ │Alert &  │  │   │
│  │  │& Children│ │File + Meta │ │Snapshot  │ │Report   │  │   │
│  │  └──────────┘ └────────────┘ └──────────┘ └─────────┘  │   │
│  └───────────────────────┬─────────────────────────────────┘   │
│                          │ subscribes to detection.*            │
│  ┌───────────────────────┴─────────────────────────────────┐   │
│  │  LAYER 3: DETECTION ENGINES                             │   │
│  │  ┌──────────────┐ ┌────────────────┐ ┌──────────────┐   │   │
│  │  │YARA Scanner  │ │Behavioral      │ │Anomaly ML    │   │   │
│  │  │8 built-in +  │ │Engine          │ │(Isolation    │   │   │
│  │  │custom rules  │ │15 ATT&CK rules │ │ Forest)      │   │   │
│  │  └──────────────┘ └────────────────┘ └──────────────┘   │   │
│  └───────────────────────┬─────────────────────────────────┘   │
│                          │ subscribes to file.* and proc.*     │
│  ┌───────────────────────┴─────────────────────────────────┐   │
│  │  LAYER 2: MONITORS (Telemetry Collection)               │   │
│  │  ┌─────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐  │   │
│  │  │FIM      │ │Process    │ │Network   │ │Resource   │  │   │
│  │  │watchdog │ │Monitor    │ │Monitor   │ │Monitor    │  │   │
│  │  │inotify  │ │psutil     │ │/proc/net │ │CPU/Mem/IO │  │   │
│  │  └─────────┘ └───────────┘ └──────────┘ └───────────┘  │   │
│  └───────────────────────┬─────────────────────────────────┘   │
│                          │ publishes events                    │
│  ┌───────────────────────┴─────────────────────────────────┐   │
│  │  LAYER 1: CORE                                          │   │
│  │  ┌──────────────┐ ┌────────────┐ ┌───────────────────┐  │   │
│  │  │Event Bus     │ │Config      │ │SQLite Event Store │  │   │
│  │  │(pub/sub)     │ │(YAML)      │ │(persistence)      │  │   │
│  │  └──────────────┘ └────────────┘ └───────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  LAYER 0: OS HARDENING (pre-deployment)                 │   │
│  │  SUID audit · Permission tightening · Cron lockdown     │   │
│  │  Kernel param tuning · Package audit                    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Specifications

### 2.1 Core: Event Bus

The central nervous system. All modules communicate through typed events.

**Event Structure:**

| Field | Type | Purpose |
|-------|------|---------|
| event_id | str | Unique ID (UUID hex, 12 chars) |
| category | EventCategory | Typed enum (e.g., "detection.yara") |
| severity | Severity | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| source | str | Module that generated this event |
| data | dict | Arbitrary structured payload |
| timestamp | float | Unix timestamp |
| mitre_attack | str | MITRE ATT&CK technique ID |
| hostname | str | For multi-host correlation |

**Subscription patterns:** `"detection.yara"` (exact), `"detection.*"` (prefix), `"*"` (all).

**Persistence:** SQLite with indexed columns for category, severity, and timestamp. Full query API.

### 2.2 Monitors (Layer 2)

| Monitor | Technology | Poll Interval | What It Watches |
|---------|-----------|---------------|-----------------|
| FIM | watchdog (inotify/FSEvents) | Real-time | File create/modify/delete/move + SHA-256 |
| Process | psutil + /proc | 500ms | Process lifecycle, cmdline, environ, parent-child |
| Network | psutil.net_connections | 1000ms | TCP/UDP connections, listeners, connection bursts |
| Resource | psutil per-process | 5000ms | Sustained CPU, memory growth rate |

### 2.3 Detection Engines (Layer 3)

**YARA Scanner:** 8 built-in rules + custom rules from rules/yara/. Subscribes to file events. Scans in background threads.

**Behavioral Engine:** 15 ATT&CK-mapped rules. Evaluates cmdline patterns (compiled regex), file paths, and environment variables.

**Complete rule set:**

| ID | Name | Severity | ATT&CK |
|----|------|----------|--------|
| AEG-001 | Reverse Shell | CRITICAL | T1059.004 |
| AEG-002 | SUID/SGID Exploitation | CRITICAL | T1548.001 |
| AEG-003 | Download and Execute | HIGH | T1105 |
| AEG-004 | Cron Persistence | HIGH | T1053.003 |
| AEG-005 | Shell Profile Backdoor | HIGH | T1546.004 |
| AEG-006 | Cryptominer Execution | HIGH | T1496 |
| AEG-008 | LD_PRELOAD Hijacking | CRITICAL | T1574.006 |
| AEG-009 | Encoded Command Execution | MEDIUM | T1059 |
| AEG-012 | Container Escape Attempt | CRITICAL | T1611 |
| AEG-013 | Systemd Service Persistence | HIGH | T1543.002 |
| AEG-014 | History Deletion | MEDIUM | T1070.003 |
| AEG-015 | System Enumeration | LOW | T1082 |
| AEG-016 | SSH Key Theft/Planting | HIGH | T1563.001 |
| AEG-017 | Data Staging for Exfil | MEDIUM | T1074.001 |
| AEG-018 | Data Destruction | CRITICAL | T1485 |

### 2.4 Response Engine (Layer 4)

**Severity to action mapping:**

| Severity | Actions |
|----------|---------|
| CRITICAL | kill_process, quarantine_file, forensic_snapshot, alert |
| HIGH | quarantine_file, alert, forensic_snapshot |
| MEDIUM | alert, log |
| LOW | log |

**Safety:** Protected PID set (own PID, parent PID, PID 1). Forensic state captured BEFORE kill. Quarantined files get permissions set to 000 with full metadata JSON.

---

## 3. Data Flow

```
OS Activity → Monitor detects → Publishes event to bus
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                  ▼
             YARA Scanner    Behavioral Engine    Anomaly Detector
                    │                 │                  │
                    └─────────────────┼─────────────────┘
                                      │
                               detection.* event
                                      │
                                      ▼
                               Response Engine
                                │     │     │
                         ┌──────┘     │     └──────┐
                         ▼            ▼            ▼
                    Kill Process  Quarantine   Forensic
                                    File      Snapshot
```

---

## 4. File Structure

```
aegis/
├── aegis/                          # Main Python package
│   ├── __init__.py                 # Version
│   ├── __main__.py                 # Entry point and orchestrator
│   ├── core/
│   │   ├── __init__.py             # EventBus, Event, EventCategory, Severity
│   │   └── config.py              # AegisConfig (YAML loader with defaults)
│   ├── monitors/
│   │   ├── fim.py                  # File Integrity Monitor (watchdog + SHA-256)
│   │   ├── process_mon.py          # Process Monitor (psutil + pattern detection)
│   │   ├── network_mon.py          # Network Monitor (connection tracking)
│   │   └── resource_mon.py         # Resource Monitor (CPU/memory anomalies)
│   ├── detection/
│   │   ├── yara_scanner.py         # YARA engine + 8 built-in rules
│   │   └── behavioral.py          # 15 ATT&CK-mapped behavioral rules
│   ├── response/
│   │   └── __init__.py             # Kill, quarantine, forensic snapshot, alert
│   └── dashboard/
│       └── terminal.py             # Rich terminal UI
├── rules/yara/custom_threats.yar   # 7 additional YARA rules
├── config/aegis.yaml               # Main configuration
├── tests/test_aegis.py             # 25 tests (all passing)
├── requirements.txt
└── setup.py
```

---

## 5. Testing (25/25 passing)

| Category | Count | Validates |
|----------|-------|-----------|
| Event Bus | 6 | Creation, serialization, pub/sub, wildcards, patterns, persistence |
| Config | 3 | Defaults, dot-access, platform detection |
| Behavioral | 6 | Reverse shell, cryptominer, LD_PRELOAD, download-execute, zero false positives |
| Utilities | 1 | Command-line entropy calculation |
| YARA | 5 | Import, compilation, detection accuracy, no false positives |
| FIM | 2 | SHA-256 hashing, baseline database CRUD |
| Integration | 2 | Full pipeline end-to-end, MITRE ATT&CK mapping coverage |

Run: `python tests/test_aegis.py`

---

*This is the source of truth for the AEGIS architecture. Update when the architecture changes.*
