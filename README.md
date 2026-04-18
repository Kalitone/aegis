# AEGIS — Adaptive Endpoint Guardian Intelligence System

A layered, open-source endpoint security system built in Python. Designed for defense-in-depth on individual hosts, scalable to network fleet deployment.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 5: HARDENING / SELF-PROTECTION                       │
│  Manifest Verify · Watchdog · Hash-Chained Audit Log        │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4: RESPONSE                                          │
│  Kill · Quarantine · Revert · Alert · Forensics             │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: CORRELATION                                       │
│  Event Correlator · ATT&CK Mapper · Threat Scorer           │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: DETECTION                                         │
│  YARA (disk + memory) · Behavioral · Sigma · Anomaly ML     │
│  · Threat Intel · Authenticode · Supply-Chain               │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1: MONITORING                                        │
│  FIM · Process · Network · Resource · Persistence · DNS     │
├─────────────────────────────────────────────────────────────┤
│  LAYER 0: CORE                                              │
│  Event Bus · Config · Logging · Data Store                  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
pip install -r requirements.txt
python -m aegis --config config/aegis.yaml
```

Then open the live triage dashboard at **http://127.0.0.1:8765**.

### CLI commands

| Command | What it does |
|---------|--------------|
| `python -m aegis` | Run the full agent (all monitors + detectors + dashboards) |
| `python -m aegis --coverage` | Print MITRE ATT&CK coverage heatmap (ASCII) |
| `python -m aegis --coverage-json` | Emit ATT&CK Navigator-compatible layer JSON |
| `python -m aegis --verify-chain` | Verify the tamper-evident event log hash chain |
| `python -m aegis --build-manifest` | (Re)build the SHA-256 manifest of config + rules |
| `python -m aegis --mem-scan` | One-shot YARA scan of running process memory |

## Components

| Module | Purpose | Status |
|--------|---------|--------|
| `aegis.core` | Event bus, config, logging, hash-chained audit log | ✅ Built |
| `aegis.monitors.fim` | File Integrity Monitor | ✅ Built |
| `aegis.monitors.process` | Process lifecycle tracker (+ Authenticode triage) | ✅ Built |
| `aegis.monitors.network` | Network connection monitor | ✅ Built |
| `aegis.monitors.resource` | CPU/Mem/IO anomaly detection | ✅ Built |
| `aegis.monitors.persistence` | Run keys, Tasks, Services, WMI, IFEO, AppInit, cron, systemd | ✅ Built |
| `aegis.monitors.dns_mon` | DNS resolution monitor (+ optional TLS SNI) | ✅ Built |
| `aegis.detection.yara_scanner` | YARA rule engine — disk **and** process memory | ✅ Built |
| `aegis.detection.behavioral` | Behavioral rule engine | ✅ Built |
| `aegis.detection.anomaly` | ML anomaly detection (Isolation Forest) | ✅ Built |
| `aegis.detection.sigma_loader` | SigmaHQ rule loader (process_creation subset) | ✅ Built |
| `aegis.detection.threat_intel` | URLhaus / Feodo / ThreatFox / DigitalSide IOC feeds | ✅ Built |
| `aegis.detection.supply_chain` | Typosquat + malicious-package DB | ✅ Built |
| `aegis.utils.authenticode` | WinVerifyTrust signature triage on every new PID | ✅ Built |
| `aegis.utils.self_protect` | Manifest verify, parent-process check, watchdog respawn | ✅ Built |
| `aegis.utils.mitre_coverage` | ATT&CK coverage heatmap generator | ✅ Built |
| `aegis.response.engine` | Automated response actions | ✅ Built |
| `aegis.dashboard` | Terminal UI dashboard | ✅ Built |
| `aegis.dashboard.web` | Local FastAPI/HTMX web dashboard (127.0.0.1:8765) | ✅ Built |

## Dependencies (Best-in-class Open Source)

- **YARA** (VirusTotal) — Pattern matching engine, the industry standard
- **watchdog** — Cross-platform filesystem event monitoring
- **psutil** — Process and system utilities (cross-platform)
- **scikit-learn** — ML anomaly detection (Isolation Forest)
- **FastAPI / uvicorn** — Local web triage dashboard
- **requests** — Threat-intel feed fetcher
- **Rich** — Terminal UI framework
- **scapy** *(optional)* — TLS SNI capture in the DNS monitor
- **winotify** *(Windows)* — Native toast notifications

## Project Structure

```
aegis/
├── aegis/                  # Main package
│   ├── core/               # Event bus, config, logging
│   ├── monitors/           # FIM, process, network, resource
│   ├── detection/          # YARA, behavioral, anomaly ML
│   ├── response/           # Kill, quarantine, alert, forensics
│   ├── dashboard/          # Terminal UI
│   └── utils/              # Shared utilities
├── rules/                  # Detection rules
│   ├── yara/               # YARA rule files
│   ├── sigma/              # Sigma rules (for SIEM export)
│   └── behavioral/         # Behavioral detection rules (YAML)
├── config/                 # Configuration files
├── tests/                  # Test suite
├── quarantine/             # Quarantined files
├── logs/                   # Runtime logs
└── data/                   # Baseline data, ML models
```

## Web Dashboard

When `dashboard_web.enabled` is true (default), AEGIS serves a local-only HTMX
UI on `127.0.0.1:8765`:

- `/` — live event stream (HTMX-polled)
- `/findings` — open detections with severity + MITRE
- `/quarantine` — quarantined files, with delete button
- `/coverage` — MITRE ATT&CK heatmap (covered vs untracked)
- `/integrity` — manifest + audit-log hash-chain verification
- `/api/events`, `/api/health` — JSON endpoints

## Self-Protection

Configure under `self_protect:` in `config/aegis.yaml`:

- `manifest_check` — SHA-256 manifest of config + every rule file; detect
  drift at startup. `strict: true` exits on mismatch.
- `parent_check` — refuse to start unless parent is `services.exe` / NSSM /
  a known shell.
- `watchdog` — spawn a detached supervisor that re-launches AEGIS if its
  PID dies unexpectedly. A clean shutdown writes a sentinel that suppresses
  the respawn.

The event log is **hash-chained** (auditd-style): every row stores
`prev_hash` + `chain_hash = sha256(prev_hash | row_payload)`. Any tamper
is caught by `python -m aegis --verify-chain`.

## License

MIT
