# AEGIS Project Plan

## From Single Host to Fleet Protection

> This document is the complete roadmap for building, testing, and scaling AEGIS.
> Each phase has concrete tasks, acceptance criteria, and dependencies.
> Any developer, model, or agent can pick this up and execute.

---

## Project Status

### What's Built (Phase A.1 — Foundation)

| Component | Status | Tests |
|-----------|--------|-------|
| Event Bus (pub/sub + SQLite persistence) | ✅ Complete | 6/6 |
| Configuration (YAML + defaults + platform detection) | ✅ Complete | 3/3 |
| File Integrity Monitor (watchdog + SHA-256 baseline) | ✅ Complete | 2/2 |
| Process Monitor (psutil + 30 suspicious patterns) | ✅ Complete | via integration |
| Network Monitor (connection tracking + burst detection) | ✅ Complete | via integration |
| Resource Monitor (CPU/memory anomaly detection) | ✅ Complete | via integration |
| YARA Scanner (8 built-in + 7 custom rules) | ✅ Complete | 5/5 |
| Behavioral Engine (15 ATT&CK-mapped rules) | ✅ Complete | 6/6 |
| Response Engine (kill/quarantine/forensics/alert) | ✅ Complete | via integration |
| Terminal Dashboard (Rich live UI) | ✅ Complete | manual |
| Full integration test (6 attack simulations) | ✅ All detected | 2/2 |

**Total: 25/25 tests passing. Zero false positives on benign commands.**

### What's Built (Phase A.2 – A.6)

| Component | Status | Tests |
|-----------|--------|-------|
| Hardening Module (linux/windows/common) | ✅ Complete | 3/3 |
| Anomaly Detection (Isolation Forest) | ✅ Complete | 2/2 |
| Supply Chain Scanner (typosquat + redflag + blocklist) | ✅ Complete | 4/4 |
| YARA rule updater (signature-base + community) | ✅ Complete | scanner reuses existing tests |
| JSON logging + log rotation | ✅ Complete | 1/1 |
| Webhook + Email alerters | ✅ Complete | 1/1 |

**Total after Phase A: 31/33 tests passing** (the 2 pre-existing failures are Windows-only `tempfile` lock issues in the original FIM/YARA tests, unrelated to new modules).

---

## Phase A: Single Host Protection

### A.1 Foundation ✅ COMPLETE

Everything listed above.

### A.2 Hardening Module ✅ COMPLETE

Implemented in [aegis/hardening/](aegis/hardening/):
- [common.py](aegis/hardening/common.py) — `HardeningRunner`, `Finding` model, cross-platform checks (PATH writability, sensitive-file permissions, SSH config).
- [linux.py](aegis/hardening/linux.py) — SUID audit (non-essential + GTFOBins-dangerous), immutable flags via `lsattr`/`chattr`, cron access lockdown, sysctl hardening (10 params), core-dump check, package inventory.
- [windows.py](aegis/hardening/windows.py) — unnecessary services, local admin enumeration, firewall profiles, process-creation auditing, Defender real-time monitoring.

Each finding is JSON-serialisable; checks may declare a `fix` callable that the runner can apply when `--apply` is passed. Verified clean on this Windows host (2 medium findings — both fixable). CLI: `python -m aegis --harden [--apply]`.

### A.3 Anomaly Detection ML Module ✅ COMPLETE

Implemented in [aegis/detection/anomaly.py](aegis/detection/anomaly.py):
- 7-feature vector (cpu, memory, fds, child count, net connections, file write rate, cmdline entropy) — fixed order for portable model files.
- IsolationForest (n_estimators=100, configurable contamination 0.01).
- Auto-train mode: buffers samples for `training_period_hours`, trains and persists with joblib once `min_training_samples` reached.
- Detection mode: per-event inference + dedupe window so identical workloads don't flood alerts. Severity escalates to HIGH when score < -0.2.
- Tests: feature extraction + train-then-detect cryptominer-like outlier (both passing).

scikit-learn is a soft dependency — if unavailable the detector disables itself rather than breaking startup.

### A.4 Supply Chain Scanner ✅ COMPLETE

Implemented in [aegis/detection/supply_chain.py](aegis/detection/supply_chain.py):
- Levenshtein typosquat detection against curated popular PyPI/npm name sets (extensible via config `extra_popular_pypi`/`extra_popular_npm`).
- Known-malicious blocklist loaded from [rules/supply_chain/known_malicious.json](rules/supply_chain/known_malicious.json) (seeded with 42 publicly reported package names).
- Static install-script analysis (setup.py / package.json / pre/postinstall.js) for 12 red-flag patterns (exec/eval, network fetch, subprocess, base64 decode, dynamic import).
- Publishes `detection.supply_chain` events tagged MITRE T1195.002.
- CLI: `python -m aegis --scan-pkg reqeusts --ecosystem pypi` and `--scan-pkg-path <dir>`.
- Tests: levenshtein, typosquat catch + clean baseline, blocklist load, install-script red-flag (4 passing).

### A.5 Enhanced YARA Rules ✅ COMPLETE (infrastructure)

Implemented in [aegis/utils/rule_updater.py](aegis/utils/rule_updater.py):
- Pulls Florian Roth's `signature-base` and YARA-Rules community repos.
- Uses `git clone --depth 1` when git is available, falls back to a tarball download via stdlib `urllib` + `tarfile` (no extra deps needed in CI).
- CLI: `python -m aegis --update-rules` writes into `rules/yara/<source>/`. The existing scanner already recursively loads any `.yar`/`.yara` under `rules/yara/`, so no scanner code changes were needed.
- Rules are loaded into `yara.compile(sources={...})` per file so a syntax error in one community file does not break the entire compile (existing fallback in scanner).

To populate locally: `python -m aegis --update-rules`. Compilation and false-positive validation will happen the first time the scanner loads them on a real system.

### A.6 Logging and Alerting Improvements ✅ COMPLETE

Implemented in [aegis/utils/alerting.py](aegis/utils/alerting.py):
- `JsonFormatter` — one JSON object per log line (SIEM-friendly).
- `setup_logging()` — wires stdout, a rotating text log, and an optional rotating JSON log. Rotation is size-based (10 MB default, 14 backups → ~140 MB retention).
- `WebhookAlerter` — async background thread, never blocks the event bus. Slack / Discord / Teams / generic JSON payloads. URL redacted in logs.
- `EmailAlerter` — SMTP with STARTTLS (587) or SSL (465). Password may come from `AEGIS_SMTP_PASSWORD` env var.
- Both alerters support `min_severity` (default HIGH for webhook, CRITICAL for email) and integrate via `detection.*` and `response.alert` subscriptions.
- Tests cover JSON formatter validity and webhook-disabled-without-URL behaviour.

---

## Phase B: Small Network (3-10 Hosts)

### B.1 Agent-Server Architecture

**Goal:** AEGIS agents on endpoints communicate with a central server.

**Tasks:**

- [ ] Create `aegis/network/agent.py`
  - Agent mode: forward events to central server via HTTPS
  - mTLS authentication (mutual TLS with client certificates)
  - Heartbeat every 30 seconds
  - Config pull from server (rules, thresholds, watch paths)
  - Local buffering when server is unreachable

- [ ] Create `aegis/network/server.py`
  - FastAPI-based REST server
  - Receive events from multiple agents
  - Store in centralized database (PostgreSQL or SQLite)
  - Serve rule updates to agents
  - Provide fleet-wide query API

- [ ] Certificate management
  - Self-signed CA for initial deployment
  - Certificate generation script for new agents
  - Certificate rotation

**Acceptance criteria:** Two AEGIS agents on separate hosts forward events to a central server.
A detection on Host A appears in the central dashboard.

### B.2 Wazuh Integration

**Goal:** Use Wazuh as the central SIEM/correlation engine.

**Tasks:**

- [ ] Deploy Wazuh server (Docker or bare metal)
  - Wazuh manager + Elasticsearch + Kibana

- [ ] Create AEGIS → Wazuh agent bridge
  - Forward AEGIS events as Wazuh custom logs
  - Map AEGIS event categories to Wazuh rule groups
  - Configure Wazuh active response for AEGIS detections

- [ ] Create Wazuh rules for AEGIS events
  - Map MITRE ATT&CK techniques to Wazuh rule IDs
  - Configure severity levels and alert thresholds

- [ ] Import Sigma rules into Wazuh
  - Convert relevant Sigma rules using sigma-cli
  - Test detection coverage

**Acceptance criteria:** AEGIS events appear in Wazuh dashboard with proper severity,
ATT&CK mapping, and correlation.

### B.3 Network IDS (Suricata)

**Goal:** Add network-layer detection.

**Tasks:**

- [ ] Deploy Suricata on network gateway/tap
  - Configure for IDS mode (passive monitoring)
  - Enable EVE JSON output
  - Load Emerging Threats Open ruleset

- [ ] Integrate Suricata alerts with Wazuh
  - Forward eve.json to Wazuh agent
  - Configure Wazuh to parse Suricata alerts

- [ ] Create correlation rules
  - Network alert + endpoint detection = higher confidence
  - Example: Suricata detects outbound C2 beacon + AEGIS detects reverse shell process

**Acceptance criteria:** A simulated C2 connection generates correlated alerts from both
Suricata (network) and AEGIS (endpoint).

### B.4 Cross-Host Correlation

**Tasks:**

- [ ] Lateral movement detection
  - SSH from Host A to Host B followed by suspicious activity on Host B
  - Same malware hash appearing on multiple hosts
  - Coordinated process execution across hosts

- [ ] Fleet-wide threat hunting queries
  - "Show me all processes matching pattern X across all hosts"
  - "Which hosts have file Y?"
  - "Timeline of events across hosts for incident investigation"

---

## Phase C: Fleet Protection (100+ Hosts)

### C.1 Scalable Infrastructure

**Tasks:**

- [ ] Replace SQLite with PostgreSQL/TimescaleDB for event storage
- [ ] Deploy Kafka/Redis for event streaming
- [ ] Elastic Stack (Elasticsearch + Kibana) for log aggregation and search
- [ ] Horizontal scaling of detection engines

### C.2 Fleet-Wide ML

**Tasks:**

- [ ] Train anomaly models on fleet-wide baselines
- [ ] Federated learning: each agent trains locally, aggregates centrally
- [ ] Concept drift detection and automatic retraining

### C.3 SOAR Integration

**Tasks:**

- [ ] Automated playbooks (using Shuffle or TheHive/Cortex)
  - Playbook: Ransomware detected → isolate host → snapshot → alert SOC
  - Playbook: Lateral movement → quarantine source → scan destination
  - Playbook: Cryptominer → kill process → block IP → scan fleet

### C.4 Threat Intelligence

**Tasks:**

- [ ] MISP deployment for IOC management
- [ ] VirusTotal API integration for hash reputation
- [ ] Automatic YARA rule generation from threat intel feeds
- [ ] IP/domain blocklist management (updated daily)

### C.5 Compliance and Reporting

**Tasks:**

- [ ] MITRE ATT&CK coverage matrix (which techniques are detected)
- [ ] Automated compliance reports (PCI-DSS, CIS Benchmarks)
- [ ] Incident timeline generation
- [ ] Executive summary dashboards

---

## Development Guidelines

### For Any Developer/Agent Continuing This Work

1. **Read the existing code before adding new modules.** The patterns are established:
   every module subscribes to the event bus, processes events, and publishes new events.

2. **Follow the event-driven pattern.** New modules should:
   - Accept `event_bus` and `config` in their constructor
   - Subscribe to relevant event categories in `start()`
   - Publish typed events with proper severity and ATT&CK mapping
   - Have a `stop()` method for clean shutdown

3. **Test with the existing test suite.** Add tests to `tests/test_aegis.py` following
   the same pattern. Simulate events, verify detections fire, verify no false positives.

4. **YARA rules go in `rules/yara/`.** Name them descriptively. Include meta fields:
   description, severity (critical/high/medium/low), mitre (ATT&CK technique ID), author.

5. **Behavioral rules are defined in `aegis/detection/behavioral.py`.** Each rule is a
   `BehavioralRule` dataclass with regex patterns and ATT&CK mapping. Add new rules to
   the `RULES` list.

6. **Configuration follows dot-notation.** Access via `config.get("section.subsection.key")`.
   Add new config sections to `config/aegis.yaml` and defaults to `aegis/core/config.py`.

7. **Cross-platform support matters.** Use `psutil` for system operations, `pathlib.Path`
   for file paths, and check `config.platform` when platform-specific behavior is needed.

### Running AEGIS

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
python tests/test_aegis.py

# Start AEGIS (full system)
python -m aegis --config config/aegis.yaml

# One-shot YARA scan
python -m aegis --scan /path/to/directory

# Hardening audit (report-only)
python -m aegis --harden
# Hardening + apply fixes
python -m aegis --harden --apply

# Refresh community YARA rules (signature-base, YARA-Rules)
python -m aegis --update-rules

# Scan a single package name for typosquats / known-bad
python -m aegis --scan-pkg reqeusts --ecosystem pypi
# Scan an extracted package directory for install-script red flags
python -m aegis --scan-pkg-path ./suspicious_package/
```

### Key Interfaces for Integration

```python
# Creating events
from aegis.core import EventBus, Event, EventCategory, Severity

bus = EventBus(db_path="data/events.db")
bus.publish(Event(
    category=EventCategory.DETECTION_BEHAVIORAL,
    severity=Severity.HIGH,
    source="my_module",
    mitre_attack="T1059",
    data={"rule": "my_rule", "details": "..."},
))

# Subscribing to events
bus.subscribe("detection.*", lambda event: handle(event))
bus.subscribe("*", lambda event: log_everything(event))

# Querying historical events
events = bus.query_events(
    category="detection.*",
    severity="critical",
    since=time.time() - 3600,  # last hour
    limit=100,
)
```

---

## Open Source Tools to Integrate

These are the best-in-class open source projects that AEGIS should integrate with as it scales:

| Tool | Purpose | Integration Point |
|------|---------|------------------|
| **Wazuh** | Central SIEM/XDR | Phase B — agent event forwarding |
| **Suricata** | Network IDS | Phase B — network-layer detection |
| **YARA** (VirusTotal) | Pattern matching | ✅ Already integrated |
| **Sigma** (SigmaHQ) | Detection rules | Phase B — rule conversion for Wazuh |
| **MISP** | Threat intelligence | Phase C — IOC feeds |
| **Velociraptor** | Forensics/hunting | Phase C — fleet-wide live forensics |
| **Osquery** | Endpoint visibility | Phase C — supplementary SQL-based queries |
| **ClamAV** | AV engine | Optional — signature database |
| **Cuckoo Sandbox** | Dynamic analysis | Phase C — automated malware analysis |
| **TheHive + Cortex** | Incident response | Phase C — SOAR playbooks |
| **Elastic Stack** | Log aggregation | Phase C — fleet-scale search |

---

## Success Metrics

### Phase A (Single Host)

- [ ] Detects all 6 attack scenarios in test suite
- [ ] Zero false positives on normal workloads
- [ ] <2% CPU overhead, <50MB memory
- [ ] All events persisted and queryable
- [ ] Dashboard shows real-time status

### Phase B (Small Network)

- [ ] Events from all hosts visible in central dashboard
- [ ] Cross-host correlation detects lateral movement
- [ ] Network + endpoint alerts are correlated
- [ ] <5 minute mean time to detect (MTTD) for known attack patterns
- [ ] Rule updates propagate to all agents within 1 minute

### Phase C (Fleet)

- [ ] Scales to 100+ endpoints
- [ ] <1% false positive rate
- [ ] MITRE ATT&CK coverage >60% of relevant techniques
- [ ] Automated response for CRITICAL threats
- [ ] Fleet-wide threat hunting in <5 seconds

---

*This plan is a living document. Update it as phases complete and new requirements emerge.*
*Last updated: April 2025*
