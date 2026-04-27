# AEGIS — Adaptive Endpoint Guardian Intelligence System

**A transparent, auditable, single-host EDR for environments where a black-box cloud-EDR is not an option.**
Air-gappable. ~7,000 lines of readable Python. Hash-chained event log. Every component does one thing.

---

## What AEGIS does, in plain English

A computer is doing thousands of things every second — programs starting, files being written, the network reaching out to other machines. **AEGIS watches all of that on one machine** and decides whether any of it looks like a real-world attack.

When something dangerous happens, AEGIS can act on its own: kill the process, lock the suspicious file in a quarantine folder, snapshot what was on the screen, hunt for ways the attacker tried to come back later, and alert you. Every step is written to a log that's mathematically impossible to edit silently — if anyone tampers with the past, AEGIS notices.

It's deliberately **single-host and offline**. There is no cloud service to phone home to, no fleet console, no central database. You install it on a machine you care about — a research workstation, an air-gapped industrial PC, a teaching lab — and that machine defends itself.

Three reasons that matters:
1. **You can read the whole thing.** Every detector, every monitor, every response action is a Python file under 800 lines. A defender who knows their stuff can audit AEGIS in a weekend. Commercial EDRs are deliberately opaque.
2. **You can prove it didn't lie.** The event log is a hash-chained ledger — like a tiny private blockchain — so a forensic auditor can mathematically verify nothing was edited after the fact. Try asking CrowdStrike to do that.
3. **You can run it where the cloud can't go.** Classified networks, hospital ICS, OT jump boxes, research labs that won't accept telemetry exfiltration. AEGIS doesn't ask the internet for permission.

---

## How it actually works (one example walkthrough)

A user clicks a phishing link and a malicious PowerShell script lands at `C:\Users\alice\Downloads\update.ps1`.

```
[1] FIM watches Downloads/. The file write fires a `file.create` event onto the bus.
       │
       ├─► [2] AmsiScanner sees `.ps1`, reads the file, hands it to Windows Defender via AMSI.
       │       Defender returns AMSI_RESULT_DETECTED (32768).
       │       AmsiScanner publishes `detection.amsi` (HIGH severity, MITRE T1059).
       │
       ├─► [3] YaraScanner also runs against the file's bytes. If a rule fires, that publishes
       │       a separate `detection.yara` event with the same case_id.
       │
       └─► [4] When the user double-clicks the .ps1 a few seconds later, ProcessMonitor
               sees a powershell.exe spawn with the suspicious file as argv[1] and publishes
               `proc.create`. AnomalyDetector scores the feature vector.

ALL of those detection events flow into the ResponseEngine.
The engine looks at the highest severity (HIGH → "quarantine_file + alert + forensic_snapshot")
and runs the 5-step chain:

   ① forensic_snapshot   → JSON dump of the process tree, env, network state at this instant
   ② quarantine_file      → file moved to ./quarantine/, chmod 0 (now unrunnable)
   ③ hash_sweep           → SHA-256 the binary, walk Downloads/ + Temp/ for siblings, quarantine them
   ④ persistence_hunt     → check Run keys / Scheduled Tasks / Services for references to that file
   ⑤ hardening_recheck    → re-baseline the host's hardening posture, publish drift events

Throughout the chain, every step publishes an event tagged with the same `case_id`,
so the dashboard's Cases view stitches the whole story onto one page.

In parallel, the alerting layer fires:
   • response.alert     → webhook (Slack/Teams/Discord/generic JSON)
   • toast              → native Windows 10/11 popup
   • ocsf JSON-line     → file the SIEM tails (Splunk Forwarder / Filebeat / Vector)
   • detection.llm_triage → local LLM produces a one-paragraph operator narrative

Every event lands in data/events.db with prev_hash + chain_hash. Tamper = caught.
```

That's the whole loop. The rest of this README is just naming the pieces.

---

## Architecture

AEGIS is a **layered pipeline glued by an in-process event bus**. Each layer publishes events; the next layer subscribes. No threads talk to each other directly except through the bus, so the whole system is reasonable to read top-to-bottom.

```
                                AEGIS — System Architecture
                                ──────────────────────────────
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                         LAYER 5 — EGRESS / OPERATOR                          │
   │                                                                              │
   │   ┌────────────┐  ┌────────────┐  ┌──────────────┐  ┌─────────────────────┐  │
   │   │  Webhook   │  │ Toast      │  │  Email       │  │  Web Dashboard      │  │
   │   │ (Slack /   │  │ (Win10/11  │  │ (SMTP)       │  │  127.0.0.1:8765     │  │
   │   │  Discord / │  │  popup)    │  │              │  │  HTMX + SSE +       │  │
   │   │  Teams /   │  │            │  │              │  │  Cases view         │  │
   │   │  generic)  │  │            │  │              │  │                     │  │
   │   └────────────┘  └────────────┘  └──────────────┘  └─────────────────────┘  │
   │                                                                              │
   │   ┌────────────────────────┐  ┌─────────────────────────────────────────┐    │
   │   │  OCSF JSON-lines sink  │  │  SBOM emitter                           │    │
   │   │  (text/event-stream    │  │  CycloneDX 1.5 → data/sbom.cdx.json     │    │
   │   │   tailed by SIEM)      │  │  pip + npm inventory, every 24 h        │    │
   │   └────────────────────────┘  └─────────────────────────────────────────┘    │
   └──────────────────────────────────────────────────────────────────────────────┘
                                          ▲
                                          │  subscribes to "*"  /  "response.*"
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                         LAYER 4 — RESPONSE ENGINE                            │
   │                                                                              │
   │   subscribes:  detection.*                                                   │
   │   publishes:   response.kill, response.quarantine, response.alert,           │
   │                response.forensic, response.persistence, response.purge,      │
   │                response.hardening_drift                                      │
   │                                                                              │
   │   ┌──────────────────────── 5-step incident chain ────────────────────────┐  │
   │   │  ① forensic_snapshot  ② quarantine_file  ③ hash_sweep                 │  │
   │   │  ④ persistence_hunt   ⑤ hardening_recheck                             │  │
   │   │                                                                       │  │
   │   │  Quarantine allow-list refuses to touch credential stores             │  │
   │   │   (OneAuth, browser profiles, .ssh, Outlook .ost/.pst, …)             │  │
   │   │  Forensics + quarantine purge on configurable retention window        │  │
   │   │  Per-source `auto_respond_sources` blocks destructive actions for     │  │
   │   │   noisy detectors (e.g. anomaly → manual-action alert only)           │  │
   │   └────────────────────────────────────────────────────────────────────────┘ │
   └──────────────────────────────────────────────────────────────────────────────┘
                                          ▲
                                          │  subscribes to detection.*
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                         LAYER 3 — DETECTION                                  │
   │                                                                              │
   │   subscribes:  proc.*, file.*, net.*, resource.*                              │
   │   publishes:   detection.yara, detection.behavioral, detection.anomaly,      │
   │                detection.supply_chain, detection.honeytoken,                 │
   │                detection.amsi                                                │
   │                                                                              │
   │   ┌────────────────┐ ┌────────────────┐ ┌────────────────┐                   │
   │   │ YaraScanner    │ │ Behavioral     │ │ AnomalyDetector│                   │
   │   │ disk + memory  │ │ + Sigma loader │ │ Isolation      │                   │
   │   │ on file events │ │ rule engine    │ │ Forest +       │                   │
   │   │ + periodic mem │ │                │ │ storm breaker  │                   │
   │   └────────────────┘ └────────────────┘ └────────────────┘                   │
   │   ┌────────────────┐ ┌────────────────┐ ┌────────────────┐                   │
   │   │ AmsiScanner    │ │ ThreatIntel    │ │ SupplyChain    │                   │
   │   │ Defender via   │ │ URLhaus / Feo- │ │ pip/npm typo-  │                   │
   │   │ AmsiScanBuffer │ │ do / ThreatFox │ │ squat + DB     │                   │
   │   │ on script files│ │ hourly cache   │ │                │                   │
   │   └────────────────┘ └────────────────┘ └────────────────┘                   │
   │   ┌────────────────────────────────────────────────────────────────────────┐ │
   │   │ LlmTriage (local LLM, advisory-only)                                   │ │
   │   │ Subscribes response.alert; publishes detection.llm_summary with        │ │
   │   │ confidence label + narrative + suggested next steps.                   │ │
   │   │ Default Qwen-2.5-3B-Instruct (Q4_K_M GGUF) via llama-cpp-python.       │ │
   │   │ NEVER feeds destructive actions — prompt injection threat is real.    │ │
   │   └────────────────────────────────────────────────────────────────────────┘ │
   └──────────────────────────────────────────────────────────────────────────────┘
                                          ▲
                                          │  subscribes to monitor topics
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                         LAYER 2 — MONITORS                                   │
   │                                                                              │
   │   publishes:   file.*, proc.*, net.*, resource.*                              │
   │                                                                              │
   │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
   │   │ FIM          │ │ ProcessMon   │ │ NetworkMon   │ │ ResourceMon  │        │
   │   │ watchdog +   │ │ psutil 500ms │ │ psutil 1s    │ │ CPU/Mem/IO   │        │
   │   │ SHA-256      │ │ poll, parent │ │ poll, listen │ │ thresholds   │        │
   │   │ baseline     │ │ tracking,    │ │ + outbound   │ │              │        │
   │   │              │ │ Authenticode │ │ port watch   │ │              │        │
   │   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘        │
   │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
   │   │ Persistence  │ │ DnsMon       │ │ HoneyMon     │ │ EbpfProcMon  │        │
   │   │ Run keys,    │ │ Win:         │ │ Decoy files  │ │ Linux only,  │        │
   │   │ Tasks, Svcs, │ │ ipconfig poll│ │ in user dirs;│ │ kernel       │        │
   │   │ WMI, IFEO,   │ │ +optional    │ │ FIM watches  │ │ tracepoint   │        │
   │   │ AppInit,     │ │ scapy SNI    │ │ for tamper   │ │ via bcc      │        │
   │   │ cron, systemd│ │              │ │              │ │              │        │
   │   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘        │
   └──────────────────────────────────────────────────────────────────────────────┘
                                          ▲
                                          │  publish() / subscribe()
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                         LAYER 1 — CORE                                       │
   │                                                                              │
   │   ┌────────────────────────────────────────────────────────────────────────┐ │
   │   │ EventBus  (aegis/core/__init__.py)                                     │ │
   │   │   • publish/subscribe with pattern matching ("file.*", "*")            │ │
   │   │   • Thread-safe, ring-buffered, persists every event to SQLite         │ │
   │   │   • Hash-chained: prev_hash + chain_hash = sha256(prev | row)          │ │
   │   │   • verify_chain() walks the chain; tamper = boom                      │ │
   │   └────────────────────────────────────────────────────────────────────────┘ │
   │   ┌────────────────────────────────────────────────────────────────────────┐ │
   │   │ AegisConfig  (aegis/core/config.py + config_schema.py)                 │ │
   │   │   • Loads YAML, deep-merges defaults, applies platform-specific        │ │
   │   │     watch paths                                                         │ │
   │   │   • Pydantic v2 validation: every typo errors with the dotted path     │ │
   │   │   • `python -m aegis --config-check` for CI gates                      │ │
   │   └────────────────────────────────────────────────────────────────────────┘ │
   └──────────────────────────────────────────────────────────────────────────────┘
                                          ▲
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │                LAYER 0 — SELF-PROTECTION (always-on)                         │
   │                                                                              │
   │   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐        │
   │   │ Manifest     │ │ TPM-bound    │ │ Process      │ │ Watchdog     │        │
   │   │ verify       │ │ ECDSA P-256  │ │ Mitigations  │ │ supervisor   │        │
   │   │ SHA-256      │ │ attestation  │ │ (Win): DEP,  │ │ respawns     │        │
   │   │ at startup   │ │ via NCrypt + │ │ ASLR, ext-   │ │ AEGIS if     │        │
   │   │              │ │ MS Platform  │ │ point dis,   │ │ PID dies     │        │
   │   │              │ │ Crypto Prov. │ │ image-load   │ │              │        │
   │   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘        │
   │   ┌──────────────┐ ┌──────────────┐                                          │
   │   │ Lockfile     │ │ Parent check │  Service ACL hardening lives in the      │
   │   │ single-      │ │ refuse start │  install scripts, not at runtime.        │
   │   │ instance     │ │ unless       │                                          │
   │   │ guard        │ │ services.exe │                                          │
   │   └──────────────┘ └──────────────┘                                          │
   └──────────────────────────────────────────────────────────────────────────────┘
```

### Event flow at a glance

| Topic | Producer | Consumer |
|---|---|---|
| `file.{create,modify,delete,move}` | `FIM`, `HoneyMon` | `YaraScanner`, `AmsiScanner` |
| `proc.{create,exit,suspicious}` | `ProcessMonitor`, `EbpfProcessMonitor`, `PersistenceMonitor` | `BehavioralEngine`, `AnomalyDetector` |
| `net.{connect,listen,close}` | `NetworkMonitor`, `DnsMonitor` | `ThreatIntel` (cross-references), `BehavioralEngine` |
| `resource.{cpu,memory,disk}` | `ResourceMonitor` | `BehavioralEngine`, `AnomalyDetector` (signal source) |
| `detection.*` | every detector | `ResponseEngine`, `LlmTriage`, `WebhookAlerter`, `OcsfFileSink`, `WebDashboard` |
| `response.*` | `ResponseEngine` | `LlmTriage` (post-hoc), `WebhookAlerter`, `EmailAlerter`, `ToastAlerter`, `OcsfFileSink`, `WebDashboard` |
| `system.{start,stop,error,health}` | `Aegis` orchestrator | `OcsfFileSink`, `WebDashboard` |

Pattern-matching: subscribe to `"detection.*"` to catch every detector; subscribe to `"*"` (wildcard) to consume the full audit stream — that's how `OcsfFileSink` and the SSE endpoint work.

---

## Module reference

### Core
| Path | Role |
|---|---|
| [aegis/core/__init__.py](aegis/core/__init__.py) | EventBus + Event/EventCategory/Severity types + SQLite persistence + hash chain + `verify_chain()` + `query_events()` + `list_cases()` |
| [aegis/core/config.py](aegis/core/config.py) | YAML loader, deep-merge over defaults, platform-specific watch-path defaults |
| [aegis/core/config_schema.py](aegis/core/config_schema.py) | Pydantic v2 model hierarchy mirroring every YAML key; soft-warn by default, strict mode on `--config-check` |

### Monitors (Layer 2 — telemetry sources)
| Path | Role | Platform |
|---|---|---|
| [aegis/monitors/fim.py](aegis/monitors/fim.py) | File Integrity Monitor — watchdog + SHA-256 baseline | All |
| [aegis/monitors/process_mon.py](aegis/monitors/process_mon.py) | psutil-based process tracker; parent-tree, cmdline, Authenticode triage | All |
| [aegis/monitors/proc_ebpf.py](aegis/monitors/proc_ebpf.py) | Push-based exec tracer via `sched_process_exec` tracepoint (bcc) | Linux only |
| [aegis/monitors/network_mon.py](aegis/monitors/network_mon.py) | psutil socket watcher, listen + outbound + suspicious-port flags | All |
| [aegis/monitors/resource_mon.py](aegis/monitors/resource_mon.py) | CPU / memory / disk-I/O thresholds | All |
| [aegis/monitors/persistence.py](aegis/monitors/persistence.py) | Run keys, Scheduled Tasks, Services, WMI subs, IFEO, AppInit_DLLs, cron, systemd | All |
| [aegis/monitors/dns_mon.py](aegis/monitors/dns_mon.py) | `ipconfig /displaydns` polling + optional scapy/npcap TLS-SNI capture | Win primary |
| [aegis/monitors/honey_mon.py](aegis/monitors/honey_mon.py) | Plants decoy files (passwords.txt, wallet.dat, .aws/credentials, …); flags any modification or deletion | All |

### Detection (Layer 3 — analysis)
| Path | Role |
|---|---|
| [aegis/detection/yara_scanner.py](aegis/detection/yara_scanner.py) | YARA on file events + periodic in-memory process scan |
| [aegis/detection/behavioral.py](aegis/detection/behavioral.py) | Cmdline-pattern + correlation-window rule engine |
| [aegis/detection/sigma_loader.py](aegis/detection/sigma_loader.py) | Translates SigmaHQ `process_creation` rules into AEGIS behavioral rules |
| [aegis/detection/anomaly.py](aegis/detection/anomaly.py) | Isolation Forest on per-process feature vectors + storm breaker |
| [aegis/detection/threat_intel.py](aegis/detection/threat_intel.py) | URLhaus / Feodo / ThreatFox / DigitalSide IOC feeds |
| [aegis/detection/supply_chain.py](aegis/detection/supply_chain.py) | pip/npm typosquat distance + known-malicious DB |
| [aegis/detection/amsi.py](aegis/detection/amsi.py) | Hands script-class files to Windows Defender via `AmsiScanBuffer` |
| [aegis/detection/llm_triage.py](aegis/detection/llm_triage.py) | Local LLM produces narrative + confidence + next-steps for each `response.alert`; ADVISORY ONLY |

### Response (Layer 4 — automated action)
| Path | Role |
|---|---|
| [aegis/response/__init__.py](aegis/response/__init__.py) | `ResponseEngine` — subscribes `detection.*`, runs the 5-step chain, allow-list gate, per-source overrides |
| [aegis/response/forensics.py](aegis/response/forensics.py) | Process-tree + execution-chain capture before destructive action |
| [aegis/response/hash_sweep.py](aegis/response/hash_sweep.py) | Sweep drop zones for SHA-256 siblings of the primary IOC |
| [aegis/response/persistence.py](aegis/response/persistence.py) | Hunt persistence surfaces for references to the quarantined file |
| [aegis/response/hardening_recheck.py](aegis/response/hardening_recheck.py) | Re-baseline hardening posture, publish drift events |
| [aegis/response/purge.py](aegis/response/purge.py) | Retention-gated quarantine + forensics rotation, secure-overwrite, evidence gate, append-only audit |

### Self-protection (Layer 0 — runs before everything else)
| Path | Role |
|---|---|
| [aegis/utils/self_protect.py](aegis/utils/self_protect.py) | Manifest verify, parent-process check, watchdog spawn, clean-shutdown sentinel |
| [aegis/utils/tpm_attest.py](aegis/utils/tpm_attest.py) | TPM-bound ECDSA P-256 manifest signature via NCrypt + Microsoft Platform Crypto Provider |
| [aegis/utils/process_mitigation.py](aegis/utils/process_mitigation.py) | `SetProcessMitigationPolicy` — ExtensionPoint, StrictHandle, ImageLoad, FontDisable |
| [aegis/utils/lockfile.py](aegis/utils/lockfile.py) | Single-instance guard against split-brain dual writers |
| [aegis/utils/authenticode.py](aegis/utils/authenticode.py) | `WinVerifyTrust` signature verification on every new PID |

### Egress (Layer 5 — operator surface)
| Path | Role |
|---|---|
| [aegis/utils/alerting.py](aegis/utils/alerting.py) | WebhookAlerter (Slack/Discord/Teams/generic), ToastAlerter, EmailAlerter, OcsfFileSink |
| [aegis/utils/ocsf.py](aegis/utils/ocsf.py) | AEGIS event → OCSF v1.1.0 mapping (Detection Finding / File System Activity / Process Activity / …) |
| [aegis/utils/sbom.py](aegis/utils/sbom.py) | Periodic CycloneDX 1.5 SBOM (pip + npm) |
| [aegis/dashboard/web.py](aegis/dashboard/web.py) | FastAPI + HTMX + SSE dashboard at `127.0.0.1:8765` |
| [aegis/dashboard/terminal.py](aegis/dashboard/terminal.py) | Rich-based TUI (legacy / dev convenience) |

### Hardening + utility
| Path | Role |
|---|---|
| [aegis/hardening/](aegis/hardening/) | `--harden` audit + apply (Windows registry, Linux sysctl/services) |
| [aegis/utils/mitre_coverage.py](aegis/utils/mitre_coverage.py) | ATT&CK heatmap + Navigator JSON layer generator |
| [aegis/utils/rule_updater.py](aegis/utils/rule_updater.py) | Daily community-rule fetcher (opt-in) |

---

## Quick start

### Install

```bash
pip install -r requirements.txt
```

Optional extras:
- **LLM triage** — `pip install llama-cpp-python` then download a GGUF into `models/` (`bartowski/Qwen2.5-3B-Instruct-GGUF` is the ship default — see [analysis_reports/04_llm_bench.md](analysis_reports/04_llm_bench.md) for why)
- **Linux eBPF** — `sudo apt install python3-bpfcc` (Debian/Ubuntu) or `sudo dnf install python3-bcc` (Fedora/RHEL)
- **Native toasts on Windows** — `pip install winotify`
- **TLS SNI capture** — `pip install scapy` + npcap

### Run

```bash
python -m aegis --config config/aegis.yaml
```

Open `http://127.0.0.1:8765` for the dashboard.

### CLI surface

| Command | Effect |
|---|---|
| `python -m aegis` | Run the full agent |
| `python -m aegis --config-check` | Strict-validate the YAML; CI-friendly (exit 5 on schema error) |
| `python -m aegis --config-schema` | Print the JSON Schema for editor autocomplete (`yaml.schemas`) |
| `python -m aegis --coverage` | ATT&CK coverage heatmap (ASCII) |
| `python -m aegis --coverage-json` | ATT&CK Navigator-compatible JSON layer |
| `python -m aegis --verify-chain` | Walk the event hash chain — fails noisily on tamper |
| `python -m aegis --build-manifest` | Re-build the SHA-256 + TPM-attested manifest |
| `python -m aegis --mem-scan` | One-shot YARA scan of every running process's memory |
| `python -m aegis --scan <dir>` | One-shot YARA on a directory |
| `python -m aegis --scan-pkg <name>` | Supply-chain check for a pip/npm package name |
| `python -m aegis --harden` | Hardening audit (`--apply` to remediate) |
| `python -m aegis --purge-quarantine` | Wipe `quarantine/` (clears the readonly bit first) |
| `python -m aegis --reset-chain --yes` | Archive `events.db` and start a fresh chain |

---

## Web dashboard

Loopback-only, single operator, no auth (yet — there's a memory note about adding bearer-token gating).

| Path | What |
|---|---|
| `/` | Live event stream, **SSE-driven** — real-time push, hover-pause, severity chips |
| `/findings` | Detection table, multi-select acknowledge/dismiss/reopen, ATT&CK column |
| `/cases` | Case rollup grouped by `case_id`; click a row to drill in |
| `/cases/{id}` | Full case timeline + first/last seen + sources + MITRE technique |
| `/quarantine` | Quarantined files; per-file delete, typed-confirm bulk purge |
| `/coverage` | MITRE ATT&CK heatmap (covered / fired / critical) |
| `/integrity` | Manifest + audit-log verification |
| `/api/events/stream` | SSE endpoint backing the live page |

---

## Configuration

Single file: [`config/aegis.yaml`](config/aegis.yaml). Top-level sections:

```
core:           paths, log levels, event DB
monitors:       fim, process, network, resource, persistence, dns, honey, proc_ebpf
detection:      yara, behavioral, anomaly, supply_chain, sigma, threat_intel, amsi, llm_triage
response:       auto_respond, severity_actions, forensics, quarantine, hash_sweep,
                persistence_hunt, purge, hardening_recheck, auto_respond_sources
dashboard:      legacy TUI knobs
dashboard_web:  loopback FastAPI host/port
self_protect:   manifest_check, strict, parent_check, watchdog, require_attestation,
                process_mitigations
rule_updates:   daily community-rule fetch
alerting:       ocsf, webhook, toast, email
```

Every section is validated by [aegis/core/config_schema.py](aegis/core/config_schema.py) — typos error with the exact field path. Run `python -m aegis --config-check` before committing a config change.

---

## Self-protection guarantees

1. **Manifest integrity** — SHA-256 of config + every rule file; mismatch at startup fails strict-mode and warns soft-mode.
2. **TPM-bound attestation** *(opt-in via `self_protect.require_attestation: true`)* — manifest is signed by an ECDSA P-256 key whose private half lives in the TPM. A stolen `integrity.manifest.json` cannot be replayed on another host because the public key won't match the destination's TPM.
3. **Process mitigations** — at bootstrap, `SetProcessMitigationPolicy` enables `ExtensionPointDisable` (no AppInit DLL injection), `StrictHandleCheck`, `ImageLoadPolicy: NoRemote+NoLowLabel+PreferSystem32`, `FontDisable`. Aggressive mode adds `ProhibitDynamicCode` and `NoChildProcessCreation` (which break `--harden` etc., so opt-in only).
4. **Single-instance lock** — file lock on `data/aegis.pid`; second start fails fast rather than letting two writers corrupt the chain.
5. **Watchdog** *(opt-in)* — supervisor process respawns AEGIS if its PID dies unexpectedly. Honors `data/.aegis_clean_shutdown` sentinel for intentional stops.
6. **Parent-process check** *(Windows opt-in)* — refuse to start unless parent is `services.exe` / NSSM / a known shell.
7. **Hash-chained event log** — every row stores `prev_hash` + `chain_hash = sha256(prev_hash || row_payload)`. `verify_chain()` walks it; tamper = caught.

---

## Data on disk

```
data/
├─ events.db                 SQLite hash-chained audit log
├─ events.db-wal             SQLite write-ahead log
├─ aegis.pid                 single-instance lockfile
├─ baseline.db               FIM SHA-256 snapshots
├─ persistence.baseline.json registry / scheduled-task / WMI snapshot
├─ honey.baseline.json       per-canary sha256 + sentinel
├─ anomaly_model.pkl         Isolation Forest (joblib)
├─ threat_intel_cache.json   IOC feed cache
├─ integrity.manifest.json   manifest + (optionally) TPM signature
├─ sbom.cdx.json             CycloneDX 1.5 (when emitter enabled)
├─ forensics/                snapshot_<epoch>_<case_id>.json
└─ .aegis_clean_shutdown     watchdog sentinel
quarantine/                  STAGED + .meta.json sidecars
logs/                        rotating text + JSON logs (+ optional OCSF)
models/                      GGUF model files for LLM triage (operator downloads)
```

---

## Project structure

```
aegis/
├── aegis/                       # Main package (~7,000 LoC)
│   ├── __main__.py              # Orchestrator — wires every component
│   ├── core/                    # EventBus, hash chain, config + schema
│   ├── monitors/                # Telemetry sources (Layer 2)
│   ├── detection/               # Detectors (Layer 3)
│   ├── response/                # ResponseEngine + 5-step chain (Layer 4)
│   ├── dashboard/               # Web (HTMX+SSE) + legacy TUI
│   ├── hardening/               # --harden audit + apply
│   └── utils/                   # alerting, ocsf, sbom, self_protect,
│                                # tpm_attest, process_mitigation, lockfile,
│                                # authenticode, mitre_coverage, rule_updater
├── rules/
│   ├── yara/                    # YARA rule files
│   ├── sigma/                   # SigmaHQ rules (process_creation subset)
│   ├── behavioral/              # Cmdline / correlation rules
│   └── supply_chain/            # known_malicious.json
├── config/aegis.yaml            # Single config; Pydantic-validated
├── tests/                       # 20 self-contained test files
├── scripts/
│   ├── bench_llm_triage.py      # Benchmark candidate LLMs against events.db
│   ├── install-service.ps1      # NSSM-backed Windows service
│   ├── install-task-userlogon.ps1
│   └── uninstall-service.ps1
├── analysis_reports/            # Audit + R&D reports
├── quarantine/                  # Created at first quarantine
├── logs/                        # Created at first log
├── data/                        # Created at first event
└── models/                      # Created when LLM triage downloads a GGUF
```

---

## Tests

20 self-contained test files. Each one is a script with a `main()` — no pytest required.

```bash
# Single suite
python tests/test_aegis.py

# Full sweep
for t in tests/test_*.py; do python "$t"; done
```

Coverage matrix:

| Suite | Validates |
|---|---|
| `test_aegis.py` | Smoke + unit tests (~36 checks) |
| `test_step{1..5}_*.py` | The 5-step response chain (attribution, hash sweep, persistence hunt, purge, hardening recheck) |
| `test_chain_concurrency.py` | Multi-writer hash-chain integrity |
| `test_quarantine_allow_list.py` | Allow-list refuses to quarantine credential stores / browser profiles |
| `test_forensics_purge.py` | Retention-gated rotation; case_ids in quarantine are protected |
| `test_anomaly_storm_breaker.py` | Severity config + rolling-window rate cap |
| `test_honey_monitor.py` | Plant / modify-detect / delete-detect / auto-replant |
| `test_process_mitigation.py` | Safe + aggressive bundle mapping (mocked Win32) |
| `test_ocsf.py` | Every EventCategory mapped; type_uid formula; sink end-to-end |
| `test_dashboard_cases_sse.py` | `list_cases` rollup; SSE stream lifecycle (uses real uvicorn on a free port) |
| `test_config_schema.py` | Shipped YAML validates clean; typos rejected at the right path |
| `test_tpm_attest.py` | Real TPM round-trip on this Win11 host; tamper detection |
| `test_sbom.py` | CycloneDX 1.5 shape; pip + npm collectors; emitter publishes event |
| `test_llm_triage.py` | Prompt redaction; output parse (incl. brace-elision recovery); engine pub |
| `test_amsi.py` | Real EICAR detection through Defender; benign baseline; scanner integration |
| `test_proc_ebpf.py` | Pure mappers; non-Linux soft-fail; stub-backed lifecycle |

---

## Where AEGIS deliberately doesn't go

- **Multi-host / cloud console.** Out of scope. The OCSF JSON-line stream is the integration point — pipe it to your Splunk / Elastic / Sentinel / Dependency-Track / Security Lake.
- **Kernel driver / minifilter.** Not a Python EDR's job.
- **AMSI Provider role** — current AMSI integration is the Client role. Full system-wide PowerShell visibility needs a signed C++ DLL or ETW subscription; tracked in project memory as a follow-up.
- **macOS first-class support.** Most code paths work; some monitors are Windows-/Linux-specific. Mac is not on the test matrix.

---

## License

MIT.

---

## Acknowledgements

The design owes its layered shape to a multi-week audit that pitted AEGIS against its own production telemetry — see [analysis_reports/00_joint_report.md](analysis_reports/00_joint_report.md) for the SWOT and the R&D backlog that drove the 10-item slate now shipped above.

Best-in-class open source we lean on:
**YARA** (VirusTotal) · **watchdog** · **psutil** · **scikit-learn** · **FastAPI** + **uvicorn** · **Pydantic v2** · **Rich** · **pyyaml** · **llama-cpp-python** *(opt-in)* · **bcc** *(Linux opt-in)* · **scapy** *(opt-in)* · **winotify** *(Windows opt-in)*.
