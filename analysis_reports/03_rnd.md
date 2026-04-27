# Aegis R&D / Forward-Looking Audit

**Date:** 2026-04-24
**Scope:** Read-only architectural review against the 2025-2026 commercial-EDR baseline. Recommends emerging tech to integrate, identifies gaps, proposes a strategic positioning.
**Reviewer note on sourcing:** WebSearch was unavailable in this session. Claims about external tooling are made from training-data knowledge of projects that are well-established and unambiguously real (Tetragon, Falco, OCSF, OpenTelemetry, Volatility 3, AMSI, Microsoft-Windows-Threat-Intelligence ETW provider, River, Phi/Llama/Qwen families). Where I would normally cite a release version or benchmark, I have written **"verify before adopt"** and grouped those into the "Open questions" section so the user can resolve them before committing dev-days.

---

## TL;DR

- **Top recommendation — adopt a local LLM triage layer (3-8B)** as a post-hoc enricher subscribed to `response.alert`. Highest impact-per-dev-day in the entire backlog: turns Aegis from "stream of severities" into "case summary + suggested next action," and unblocks every other UX improvement on the dashboard side. ~5-8 dev-days.
- **Biggest architectural gap — telemetry source quality.** Aegis is polling-based (psutil at 500 ms, `ipconfig /displaydns` at 30 s). Commercial EDRs consume kernel events the same instant they happen, via ETW on Windows and eBPF on Linux. This is the one gap that single-handedly caps detection quality regardless of how many rule layers you add on top.
- **Repositioning take — Aegis should explicitly position as an *air-gapped, single-host, audit-grade* EDR and a *teaching/research* platform, NOT as a CrowdStrike alternative.** The hash-chained event log, the manifest verifier, the 5-step response chain with case attribution, and the Pythonic readability are unique strengths that commercial EDRs deliberately don't expose. Lean into that.

---

## 1. Architectural Gaps vs Commercial EDR (2025-2026 baseline)

| Gap | Commercial EDR has it | Aegis has | Worth closing for Aegis? |
|---|---|---|---|
| Kernel-mode driver / minifilter for FS + process events | Yes (CrowdStrike CSAgent.sys, S1 SentinelAgent.sys, MDE MsSense.sys) | No — userland watchdog + psutil polling | **No.** Building/signing a Windows kernel driver is a multi-month, $500+/yr EV-cert project. Out of scope for a Python EDR. |
| ETW Threat-Intelligence provider (Microsoft-Windows-Threat-Intelligence) | Yes (PPL-protected, AV/EDR-only) | No | **Partial.** The TI provider itself requires PPL (skip). But the *kernel logger* + *Microsoft-Windows-Sysmon* + *AMSI* providers are open and 10× richer than psutil. **Worth closing.** |
| eBPF telemetry (Linux) | Yes (S1, Cilium-based vendors) | No | **Yes** — `bcc`/`bpftrace`/Tetragon make this far more achievable than the Windows kernel-driver equivalent. Highest-ROI Linux telemetry upgrade. |
| AMSI integration (Windows) for PowerShell / JScript / WMI / Office macros pre-execution | Yes | No | **Yes** — AMSI is documented public API, callable from Python via ctypes. Single largest blind spot today: PowerShell command-line + script-block telemetry. |
| In-process memory scanning of every running process | Yes (continuous) | Yes — `--mem-scan` one-shot + optional periodic loop (`detection.yara.memory_scan`) | **Already present.** Verify perf cost is acceptable on real workloads; consider a per-process delta scan. |
| Ransomware honeypot files | Some (S1, Sophos InterceptX) | No | **Yes** — extremely cheap (10 canary files in user dirs + a FIM watcher). Disproportionately powerful tripwire. |
| Behavioural ML at syscall level | Yes (proprietary) | Isolation Forest on per-process feature vectors | **Skip the syscall ML rebuild.** Replace/augment with sequence-aware methods (see ML section). |
| Lateral-movement detection across hosts via central console | Yes (table-stakes) | No (single-host design) | **Skip.** Multi-host correlation is a different product. The hash-chained log + OCSF export (recommended below) is enough to feed a central SIEM if the user wants one. |
| SBOM tracking of installed packages | Some (CrowdStrike Falcon Discover, S1 Singularity Vulnerability Mgmt) | Partial — `SupplyChainScanner` covers pip/npm typosquats reactively | **Partial — worth closing.** Add a periodic CycloneDX/SPDX SBOM emit for the host (pip + npm + system packages). Maps directly onto `detection/supply_chain.py` in `evaluate_and_publish`. |
| Process-tree / behavioural attack-graph correlation | Yes | Partial — case context in `_build_case_context()` captures execution chain | **Already present in v1 form**, but score-weighted graph correlation (e.g. lsass→cmd.exe→wmic chain) is a real upgrade. See ML section. |
| Hardware-rooted integrity (TPM-bound manifest, measured boot attestation) | Some (MDE, Falcon Identity Protect) | Plain SHA-256 manifest in `aegis/utils/self_protect.py` | **Partial.** TPM-sealed manifest is achievable on Windows 11 and modern Linux; meaningful for the "audit-grade" positioning. Prioritise after LLM + eBPF/ETW. |
| Process Mitigation Policies (Windows) — DEP, ASLR, CFG, dynamic-code disable, signed-DLLs only, child-process disable, PPL | Yes (self-applied to their own agent) | No | **Yes** — call `SetProcessMitigationPolicy` early in `__main__.py` Aegis bootstrap. ~30 LoC, makes Aegis's own surface area materially harder to abuse. |

**Bottom line:** the gaps that *matter* are telemetry-source gaps (ETW, eBPF, AMSI) and a couple of cheap wins (honeypots, mitigation policies, SBOM). The "build a kernel driver / build syscall ML / build a multi-host console" gaps are CrowdStrike-rebuild territory and should be explicitly out-of-scope.

---

## 2. Top 5 Emerging Tech to Adopt — RANKED by ROI

| Rank | Tech | What it solves | Effort | Risk | Verdict |
|---|---|---|---|---|---|
| 1 | **Local LLM alert triage** (Phi-3.5-mini, Llama-3.2-3B, or Qwen-2.5-7B via llama.cpp / ollama) | Turns alert dumps into "what happened, why it matters, what to do next." Suppresses obvious FPs. Generates case-narrative for `response.alert` payloads. | 5-8 dev-days | Low — runs offline, no PII egress, cleanly bolted onto `response.alert` subscriber | **Adopt.** Single biggest UX leverage. See ML section for design. *Verify before adopt:* current best-in-class small model for security narrative tasks (the field moves quarterly). |
| 2 | **eBPF on Linux via `bcc` or `python-bpfcc`** | Replaces psutil polling with kernel event stream — `execve`, `connect`, `openat`, etc., 0-loss, microsecond latency. Solves the "polling missed a 200 ms PID" problem. | 8-12 dev-days for parity with current process_mon + network_mon | Medium — requires CAP_BPF/root; kernel version drift; container/VM gotchas | **Adopt (Linux only).** Tetragon is the production reference if user wants a managed framework. *Verify before adopt:* whether `bcc` Python bindings or `python-bpfcc` is the current preferred path. |
| 3 | **ETW userland providers + AMSI** (Windows) | PowerShell script-block logging, AMSI pre-exec scan, Microsoft-Windows-Sysmon equivalent, kernel-logger network/process events — all without a driver. | 10-15 dev-days for a new `monitors/etw_mon.py` | Medium — `pywintrace` / `python-etw` ecosystem is fragmented; AMSI provider registration via ctypes is well-documented but fiddly | **Adopt (Windows only).** This is the Windows analogue to gap #2; same impact. *Verify before adopt:* state of `pywintrace`/`krabsetw`-style Python wrappers in 2025-2026. |
| 4 | **OCSF event-schema mapping** (Open Cybersecurity Schema Framework) | Aegis emits its own schema today. Mapping core categories to OCSF unlocks Splunk/Elastic/QRadar/Sentinel ingestion with zero per-vendor work, and makes the hash-chained log a *credible audit artifact* outside Aegis. | 3-5 dev-days for a translation layer in `utils/alerting.py` | Low — OCSF is now an established LF Project, schema is stable, JSON serialization is straightforward | **Adopt.** Disproportionately strategic for the "audit-grade" positioning. Pairs with #1: emitting LLM-generated case narratives in OCSF format means downstream SIEMs get the human-readable enrichment too. |
| 5 | **Honeytokens / canary files + canary registry keys** | Tripwires for ransomware (canary files), credential theft (fake `credentials.json` + DPAPI dummy), and recon (canary registry keys monitored for ANY read attempt). | 2-3 dev-days as a new `monitors/honey_mon.py` | Very low | **Adopt.** Lowest-effort, highest-conviction detection added to the system. Uses the FIM you already have. |

**Honourable mentions / partial verdicts:**
- **OpenTelemetry (Aegis observing itself):** good citizen behaviour but not *security-relevant*. Skip until the user runs Aegis on more than one host.
- **memflow / Volatility 3 on demand:** valuable as an *operator-triggered* capability ("dump suspect PID for offline analysis") rather than a continuous monitor. **Partial — adopt as a CLI subcommand only**, ~3 dev-days.
- **Sigma rule auto-generation from observed FP/TP patterns:** interesting but premature; needs a year of triage labels first. The LLM (rec #1) is a better near-term fit for the same goal — it can *suggest* a Sigma rule from an alert + operator note.
- **Process Mitigation Policies (Windows):** ~half a dev-day, just do it. Counts as "table stakes" not "emerging."
- **TPM-backed manifest:** worthwhile for audit-grade positioning, but treat as Phase 2. ~3-5 dev-days. *Verify before adopt:* Python TPM 2.0 binding maturity (`tpm2-pytss`).
- **Cilium Hubble / Falco comparisons:** Falco is the closest spiritual cousin to Aegis on Linux — its rule language and event-source design are worth studying before committing to an eBPF design. Hubble is network-observability, less directly applicable.

---

## 3. Dashboard UX Evolution

The current dashboard (`aegis/dashboard/web.py`) is **fine for v1** — HTMX polling at 1 s on loopback is the right zero-friction default, and the inspector pane + multi-select bulk actions are already past the bar most hobby EDRs clear. Recommendations, in order:

1. **Replace `/api/events` polling with Server-Sent Events (SSE).** Not WebSockets — SSE is one-way (server→browser), trivially supported by FastAPI's `StreamingResponse`, and the browser auto-reconnects. ~1 dev-day. Keeps HTMX for everything else; just swap the event-stream endpoint.
2. **Add a token-gate even on 127.0.0.1.** Any local-malicious process can hit `127.0.0.1:8765` today. A single bearer token, generated at install time and stored at `data/dashboard.token` (mode 0600), checked in a FastAPI middleware, closes that. ~0.5 dev-days.
3. **Materialised view for filter/search.** SQLite WAL handles 100k events fine, but once `events.db` crosses ~1 M rows the existing indexes leave full-text-ish queries (`description LIKE '%mimikatz%'`) sluggish. Add an FTS5 virtual table mirroring `(rule_id, rule_name, description, data)` and a trigger to keep it in sync. ~2 dev-days.
4. **Skip native (Tauri/Electron).** Adds packaging burden without solving any user problem; loopback HTML is faster and more accessible than a native app for this scale.
5. **Case-management workflow.** The data model already supports it — `case_id` flows through `_build_case_context`, quarantine meta, persistence hits, hardening drift. The dashboard just doesn't show cases yet. Add `/cases/{id}` view that joins events on `case_id`. **This is the highest-impact dashboard change** — operators think in cases, not events. ~3 dev-days.

**Recommended path:** SSE + token + cases view. Skip the native rewrite. Skip materialised views until you have the row count to justify them.

---

## 4. ML Evolution Path

**Single recommendation — augment, don't replace, the Isolation Forest.** Specifically, layer on a **local LLM as the post-detection enricher** (rec #1 above). Reasoning:

- **Online-learning anomaly (River, Half-Space-Trees):** worthwhile for true streaming adaptation, but the current IF model is small (832 KB), retrains in seconds, and the per-host training distribution is stable. The pain point isn't drift — it's that the IF emits a score, not a *story*.
- **Sequence/Transformer process-tree models:** academically interesting, real-world FP rates are high without labelled data, and you'd need a labelling pipeline you don't have. Skip.
- **Graph-based anomaly on process spawn graphs:** belongs in correlation, not raw detection. Already partially served by `_build_case_context` — extending that into a cycle-detecting / fan-out-scoring graph metric is ~2-3 dev-days and is *complementary* to the LLM, not a substitute.
- **Local LLM for alert summarisation + investigation suggestions:** highest leverage. The model doesn't need to be smart, just to read a JSON event + the `case` context and produce: (a) a one-paragraph human summary, (b) a confidence label (likely-FP / suspicious / very-likely-malicious), (c) up to three suggested next steps. Run via `llama.cpp` server in a sidecar process, JSON-RPC over loopback, fully offline. Token-budget keeps inference under 500 ms.

**Concrete design:**
- New module `aegis/detection/llm_triage.py`. Subscribes to `response.alert`. Builds a redacted prompt (no env vars, no file contents — paths and rule IDs only). Publishes a `detection.llm_summary` event back onto the bus.
- The dashboard inspector pane shows the LLM narrative inline.
- *Verify before adopt:* current SOTA small model for instruction-following + JSON-mode output (Phi-3.5-mini, Llama-3.2-3B, Qwen-2.5-7B-Instruct are all plausible — pick by benchmark on a held-out set of Aegis events).

---

## 5. Config + Integration + Packaging

### Config (`config/aegis.yaml`)
The current YAML is well-organised with section comments — better than most projects. Two upgrades worth making:

1. **Pydantic v2 typed config.** Replace the `AegisConfig.get("foo.bar.baz", default)` pattern with a Pydantic model in `aegis/core/config.py`. Forces validation at load (catches typos like `mininum_severity`), gives IDE auto-complete, generates JSON schema for documentation. ~2 dev-days, mostly mechanical.
2. **Skip hot-reload, skip migrations.** Aegis is a long-running service; SIGHUP-style reload is a complexity sink for dubious benefit (operators can `net stop AEGIS && net start AEGIS`). Versioned migrations matter once you have shipped to >1 user — premature today.

### Integration hooks (output side)
Current state: webhook (Slack/Teams/Discord/generic), email, Windows toast, structured JSON file log. Recommended additions, ranked:

1. **OCSF + syslog/CEF export.** See rec #4 above. The structured JSON log already exists in `JsonFormatter` — emit a parallel OCSF-mapped stream and you have SIEM integration for free. ~3 dev-days.
2. **Sigma rule export of *findings*.** The Sigma loader is import-only today. A reverse path — when an operator confirms an alert is true-positive, *generate* a Sigma rule from the triggering event — is a real differentiator for the teaching/research positioning. ~2 dev-days, but probably better fronted by the LLM (rec #1) than hand-written.
3. **MISP/OpenCTI consumer (not exporter).** Already partially served by `ThreatIntel`. Adding MISP feed support is ~1 dev-day.
4. **Slack/Teams native vs webhook:** skip. The generic webhook is fine; "native" buys you nothing real.
5. **Wazuh integration:** skip. Wazuh occupies a different niche (agent → manager) and integrating in either direction is more work than it earns.

### Packaging / deployment
1. **PyInstaller single-file binary** for the *operator CLI subset* (`--scan`, `--scan-pkg`, `--harden`, `--coverage`) — useful for ad-hoc forensic work on hosts that don't have Python. ~1 dev-day.
2. **MSI/.deb/.rpm for the service installer**: deferred. NSSM/systemd works, packaging is high-toil, and the audience for Aegis (research/teaching/single-host) is comfortable with `pip install` + a script.
3. **Container image:** **skip and document why.** Running an EDR inside a container subverts most of its premise (it can't see the host). Provide a host-mount example *only* for development/CI, never production.
4. **Rust/Go core with Python plugin layer:** thought-experiment territory. The core hot path is the event bus (`aegis/core/__init__.py`), which is already SQLite-bound. Rewriting that in Rust gains nothing; the bottleneck is psutil polling, which Rust would not magically fix. The right answer is "fix telemetry sources (ETW, eBPF), keep Python." Re-evaluate only if the user ever wants to deploy to thousands of hosts.

---

## 6. Holistic Project Review

### What is Aegis good at, that commercial EDRs are *bad* at?

1. **Auditability.** The hash-chained event log (`_persist_event` in `aegis/core/__init__.py`) with `verify_chain()` is unusual in any EDR price tier — you cannot ask CrowdStrike to prove cryptographically that no event was retroactively edited. Aegis can. **Lean into this.**
2. **Readability + extensibility.** Every detector, every monitor, every response action is a Python file under 800 LoC. A defender-engineer can read the entire system in a weekend. Commercial EDRs are deliberately opaque.
3. **Integrated 5-step response chain with case attribution.** `_build_case_context` captures the execution chain *before* kill/quarantine destroy it; `case_id` flows through every downstream artefact. Most open-source EDR-likes (Wazuh, OSSEC) treat detection and response as separate concerns.
4. **Air-gap-friendly.** No call-home, no telemetry phone-home, threat-intel feeds are explicit/configurable/optional. This is a *positioning* the entire commercial EDR market actively cannot occupy.

### Right to win — proposed positioning

> **"Aegis is a transparent, auditable, single-host EDR for environments where a black-box cloud-EDR is not an option: classified/air-gapped hosts, research labs, teaching environments, OT/ICS jump boxes, and security professionals who want to understand what their EDR is actually doing."**

This is a real, defensible market segment. CrowdStrike will not build it. SentinelOne will not build it. Wazuh occupies adjacent space (SIEM + agent-manager) but is not response-chained or hash-chain-audited.

### Double down

- **Hash-chained event log** — already a differentiator. Add OCSF export (rec #4) so the chain is portable evidence.
- **Manifest verification + self-protect layer** — extend with TPM-sealed manifest for Windows 11 / measured-boot Linux.
- **The 5-step response chain with case attribution** — write it up as the marquee architectural artefact. This is the single most "real EDR" thing in the project.
- **MITRE ATT&CK coverage reporting** (`utils/mitre_coverage.py`) — keep investing. Coverage maps are the standard way buyers evaluate EDRs; Aegis already produces a Navigator-compatible JSON layer, which is rare for an open-source tool.

### Cut / deprioritise

- **Email alerter** (`EmailAlerter` in `utils/alerting.py`) — webhook + toast covers the use cases; SMTP is config-heavy and rarely used in the target deployments.
- **`network_mon.SUSPICIOUS_PORTS` static list** — false-positive heavy, decade-old heuristics. Replace with threat-intel-driven scoring or remove.
- **Sigma loader's broad `enabled: false` default** — either commit to it as a first-class detector (raise quality, enable by default) or drop. Half-supported is worse than not supported.
- **Windows toast alerting via `winotify`** — works, but the dashboard is a better surface for triage. Keep but treat as a non-critical channel.
- **Anomaly retrain cadence in YAML config** — either auto-retrain weekly on a fixed schedule or remove the configurability. The current "training_period_hours: 24, min_training_samples: 200" knobs invite misconfiguration.

### Strategic repositioning

- **Drop "competing with CrowdStrike" framing entirely.** It's not the goal and it sets the wrong success criteria.
- **Lead with the audit-grade and teaching narrative.** README hero section should mention: hash-chained log, single-host, air-gappable, every component readable in <800 LoC.
- **Explicitly out-of-scope:** kernel drivers, multi-host correlation, cloud workloads, Mac. Naming what's *not* in scope is as important as naming what is.

---

## 7. Recommended R&D Backlog — RANKED

| # | Item | Effort (dev-days) | Why this rank |
|---|---|---|---|
| 1 | Local LLM triage module (`detection/llm_triage.py`) on `response.alert` | 5-8 | Highest UX impact; turns Aegis from severity stream into case stories. |
| 2 | OCSF event-schema export | 3-5 | Strategic for "audit-grade" positioning; cheap; pairs with #1. |
| 3 | Honeytoken monitor (`monitors/honey_mon.py`) | 2-3 | Lowest effort, very high signal-to-noise detection. |
| 4 | AMSI integration (Windows) for PowerShell/JScript pre-exec | 5-8 | Closes the largest *single* Windows blind spot. |
| 5 | Cases view on dashboard + SSE replacement for polling | 4-5 | Operators triage in cases, not events; SSE is the right primitive. |
| 6 | Process Mitigation Policies on Aegis bootstrap | 0.5-1 | Quick win for self-protect surface area. |
| 7 | eBPF-based `monitors/proc_ebpf.py` (Linux) | 8-12 | Largest *single* Linux telemetry upgrade; deferred behind LLM because LLM benefits both platforms. |
| 8 | Pydantic-typed config | 2 | Mechanical, high QoL. |
| 9 | TPM-sealed manifest | 3-5 | Phase 2 — depends on user choosing the audit-grade positioning. |
| 10 | SBOM emission (CycloneDX) for the host | 2-3 | Plugs into existing supply_chain scanner. |

**Total Phase 1 (items 1-6): ~20-30 dev-days.** That's a tight, opinionated quarter of work that materially repositions the project.

---

## 8. Open Questions / Strategic Decisions for the User

1. **Positioning commit.** Are you willing to publicly position Aegis as "audit-grade single-host research EDR" rather than "open-source CrowdStrike alternative"? The R&D backlog above is shaped for the former; if you want the latter, eBPF + ETW + multi-host correlation move to the top and the LLM moves down.
2. **Local LLM model choice.** Phi-3.5-mini, Llama-3.2-3B-Instruct, and Qwen-2.5-7B-Instruct are all plausible 2025-vintage candidates for offline triage. Pick by running each on a held-out set of last-quarter Aegis alerts and judging the narratives. **This needs WebSearch / hands-on benchmarking that I could not do in this session.**
3. **Windows ETW Python ecosystem state.** `pywintrace`, `krabsetw` Python bindings, and roll-your-own ctypes are all options; the right choice depends on which is actively maintained as of 2026. **Verify before committing dev-days to rec #3.**
4. **Linux eBPF binding choice.** `bcc`/`python-bpfcc` vs running Tetragon as a sidecar and consuming its events. The latter is faster to build, the former gives more control. Pick once a target Linux distro family is settled.
5. **Drop Mac entirely?** Aegis already ignores macOS for the most part. Making this an explicit non-goal simplifies every design decision downstream.
6. **OCSF mapping ownership.** OCSF schema evolves; mapping maintenance is recurring effort. Decide whether to map only `detection.*` and `response.*` (small, stable surface) or attempt the full event vocabulary (larger, more maintenance).
7. **Dashboard auth model.** Bearer token in a 0600 file is the suggestion; an alternative is OS-user-level UDS with peer-cred check on Linux + named pipe ACL on Windows — more secure, more complex. Pick once you know if multi-operator is ever in scope.

---

*End of report. ~2,100 words. The single highest-leverage commit is item #1: a local LLM triage module subscribed to `response.alert`. Everything else compounds on top of that case-narrative foundation.*
