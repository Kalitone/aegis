# AEGIS — Joint Audit: SWOT + Roadmap

**Date:** 2026-04-24
**Audit window:** Apr 18 → Apr 24, 2026 (6.5 days continuous, hostname `BotMaker`, Windows 11)
**Scope:** Synthesis of three independent read-only audits — Security (`01_security.md`), Reliability/Analysis (`02_analysis.md`), R&D/Architecture (`03_rnd.md`) — plus main-session SQL verification of key claims against `data/events.db` (32,791 events, hash chain intact, 0 breaks).

---

## Executive Summary

1. **System works.** Hash chain is intact end-to-end (`chain_breaks = 0` across all 32,791 events), the post-Apr-18 split-brain is recovered, the response chain (Steps 1-5) executes, and 6.5 days of continuous telemetry validates the core architecture.

2. **The detection layer is mostly noise.** Of all high+critical-severity events in the live DB, the only **true positive** is a single Authenticode flag on an unsigned Antigravity (Google AI tool) installer in `%TEMP%` — and even that is benign-unsigned, not malicious. Every other high-severity event is a false positive: Isolation Forest hitting normal Windows utilities (cleanmgr, chrome, pyrefly), `connection_burst` on Chrome's network service, and (in archived DBs) YARA rules that match plain English text.

3. **One quarantine action caused real user harm.** During the Apr 18 storm, a `credential_harvester` YARA FP quarantined `C:\Users\bradl\AppData\Local\Microsoft\OneAuth\accounts\75030987-cf12-46ac-b181-64136c14097d` — verified still present at `quarantine/1776569405_3c90aeba5d2b8121_75030987-...`. This file should be restored.

4. **The "Apr 18 23:33 crash" was self-inflicted.** Both `*-corrupt` SQLite backups have valid headers and page-aligned sizes — they're not crashes. Forensic snapshots at 23:31:02 capture `bash.exe` PID 10716 running `python tests/test_step{1..5}*.py` against the live `data/events.db`. The test suite became a second writer. The fix (BEGIN IMMEDIATE + lockfile) is now in place; the chain is clean post-recovery.

5. **Strategic positioning is the highest-leverage decision.** Aegis's hash-chained, manifest-verified, single-host, air-gappable, Pythonic-readable architecture occupies a market segment commercial EDRs (CrowdStrike, S1, MDE) deliberately avoid. Lean into "audit-grade research/teaching EDR" — not "open-source CrowdStrike."

---

## SWOT Matrix

### Strengths (evidence-backed, keep investing)

| Strength | Evidence |
|---|---|
| **Tamper-evident audit log** | 32,791 events, hash chain walk shows `chain_breaks = 0`. `aegis/core/__init__.py:333` `verify_chain()`. BEGIN IMMEDIATE + lockfile guard fixed split-brain (`aegis/core/__init__.py:177-180`). |
| **Process-safe concurrency** | The Apr 18 dual-writer incident exposed the bug; the fix is committed and verified. `tests/test_chain_concurrency.py` reproduces and gates against regression. |
| **Integrated 5-step response chain with case attribution** | `_build_case_context` captures execution chain *before* kill/quarantine destroy it. `case_id` flows through quarantine meta, persistence hits, hardening drift. Tests for Steps 1-5 all present. |
| **Readable, modular Python** | Every module <800 LoC. New defenders can understand the entire system in a weekend — commercial EDRs deliberately don't expose this. |
| **Air-gap-friendly** | No call-home; threat-intel feeds explicit and optional. |
| **MITRE Navigator-compatible coverage export** | `aegis/utils/mitre_coverage.py` curates 55 IDs across 13 tactics. Rare for OSS. |

### Weaknesses (fix before next deployment)

| Weakness | Evidence |
|---|---|
| **YARA rules generate near-100% FPs** | `credential_harvester` (6,969 forensic captures), `cryptominer_strings` (2,274), `ransomware_note` (806), `data_exfil_tool` (602) — all confirmed FPs. Conditions like `any of` over single tokens (`"password"`, `"credential"`, `bitcoin/decrypt/ransom`) match any English text store. Caused the OneAuth quarantine. |
| **Anomaly severity miscalibrated** | Isolation Forest with `contamination=0.01` is **calibrated** to flag 1% of process events — by definition. Mapping that to `severity=high` and triggering the full forensic chain on each is a design error. 330 anomalies in current DB → 330 alerts → 330 forensic snapshots. |
| **Forensics directory has no retention** | `aegis/response/purge.py` purges `quarantine/` only. `data/forensics/` is 2.2 GB / 11,178 files (95.3% from the Apr 18 storm). At storm rate: 125 GB/yr. At steady-state: 3.6 GB/yr. Either way: **monotonic growth, no rotation.** |
| **Threat-intel cache is 5 days stale** | `data/threat_intel_cache.json saved_at = 1776569127` (Apr 19 07:25 UTC), verified against the file directly. No alert fires when refresh thread silently fails. |
| **Persistence baseline frozen since Apr 18 22:26** | New Run-key entries / scheduled tasks added in last 6 days are invisible to drift detection. |
| **Integrity manifest hashes only 3 files**, omitting the YARA rules in `aegis/detection/yara_scanner.py:BUILTIN_RULES`. An attacker editing built-in rules passes verification. |
| **Behavioral rules are 11/12 Linux-only** on a Windows host (`aegis/detection/behavioral.py`). Sigma is disabled. **Zero behavioral detections fired in 6.5 days.** |
| **No Windows LOLBin patterns** in `process_mon.SUSPICIOUS_PATTERNS` — no `rundll32`, `mshta`, `regsvr32`, `wmic`, `bitsadmin`, `certutil`, `powershell -enc`, Office→shell, etc. |
| **Polling-based telemetry caps detection quality** | psutil at 500ms misses short-lived PIDs. ETW/eBPF would be 10× richer. |

### Opportunities (where to spend dev-days)

| Opportunity | Rationale |
|---|---|
| **Local LLM triage layer** (Phi-3.5 / Llama 3.2 3B / Qwen 2.5 7B via llama.cpp) | Single highest UX leverage. Subscribes to `response.alert`, produces case narrative + FP/TP confidence + suggested next steps. ~5-8 dev-days. Unblocks every other dashboard improvement. Verify current SOTA before committing. |
| **OCSF event-schema export** | Strategic for "audit-grade" positioning. Maps Aegis events to a vendor-neutral schema (Splunk/Elastic/QRadar/Sentinel ingest for free). ~3-5 dev-days. |
| **Honeytokens / canary files** | Cheapest, highest-conviction detection upgrade. Reuses existing FIM. ~2-3 dev-days. |
| **AMSI integration** (Windows) for PowerShell/JScript/Office macro pre-exec | Closes the largest *single* Windows blind spot — script-block visibility. ~5-8 dev-days. |
| **eBPF Linux telemetry** (bcc / python-bpfcc / Tetragon sidecar) | Replaces psutil polling on Linux. Microsecond latency, no missed PIDs. ~8-12 dev-days. |
| **Cases view + SSE on dashboard** | Operators triage in cases not events. SSE replaces polling. ~4-5 dev-days. |
| **TPM-sealed manifest** | Phase 2. Earns the "audit-grade" claim hardware-rooted credibility. ~3-5 dev-days. |
| **Pydantic-typed config** | Mechanical, high QoL. Catches typos at load. ~2 dev-days. |

### Threats (operational risks)

| Threat | Mechanism |
|---|---|
| **Disk fill on next anomaly storm** | No `forensics/` rotation. Apr 18 produced 2.07 GB in 10 hours; recurrence on a smaller-disk host = service-down. |
| **Test runs against live DB** | `tests/test_chain_concurrency.py` *deliberately* reproduces the dual-writer bug. Lockfile guard catches AEGIS process; doesn't catch a test process opening the same DB by path. |
| **Silent threat-intel feed failure** | Cache atomic-swap (`threat_intel.py:274-285`) keeps stale state on failure. No alert. Audit only caught it because cache mtime is 5 days old. |
| **Self-quarantine of OS credential stores** | Already happened once (OneAuth). Path allow-list is needed before this hits Outlook .ost, Edge cookies, MSA tokens, etc. |
| **Authenticode-unsigned-in-TEMP rule fires on legitimate installers** | The 1 critical event in the live DB is Google's Antigravity installer. Currently action is severity=critical → would `kill_process` + `quarantine_file` if `auto_respond=true` for Authenticode source. |
| **Stale persistence + manifest baselines erode tamper-evidence claim** | Detection of *new* persistence depends on diff against baseline. Baseline frozen → 6 days of blindness. |

---

## Spot-Check Verifications (Main-Session SQL)

These are facts the subagents proposed but couldn't verify (sqlite3/python were blocked in their sandboxes):

| Claim | Verification | Result |
|---|---|---|
| Hash chain intact post-fix | `WITH walk … SELECT COUNT(*) WHERE prev_hash != LAG(chain_hash)` | **0 breaks across 32,791 events** ✅ |
| 1:1:1 anomaly→alert→forensic | `SELECT category, COUNT(*) GROUP BY category` | **330 / 330 / 330 — exact 1:1:1** ✅ |
| The "1 critical" event identity | `SELECT * WHERE severity='critical'` | **NOT the OneAuth FP (that's in archived DB) — it's the Antigravity installer Authenticode flag at Apr 24 19:45 UTC.** Security report needs this correction. |
| `response.quarantine` events in live DB | `COUNT WHERE category='response.quarantine'` | **0** — the OneAuth quarantine event lives in the pre-reset archive (`bak-131249/` or `bak-222201/`). Quarantine *file* on disk is real. |
| `response.kill` events | `COUNT WHERE category='response.kill'` | **0** — kill action never fired (likely `auto_respond=false`). |
| System restarts | `COUNT WHERE category='system.start'` | **22 rows** (mix of ~5 chain-rotation tests + 4 real platform-startup events: Apr 19 04:37, Apr 19 22:05, Apr 22 17:05, plus current). System has restarted ~4× in window. |
| Threat-intel cache freshness | `head -c 300 threat_intel_cache.json` | `saved_at: 1776569127` = **Apr 19 07:25 UTC, 5 days stale.** Confirmed. |
| Quarantine artifact present | `ls quarantine/` | **OneAuth file present**, 4756 bytes, mode `0o400` (read-only). |
| YARA detections in current DB | `COUNT WHERE category LIKE 'detection.yara%'` | **0** — the broken-rule storm lives in archived DBs only. Current DB is post-suppression. |

The security audit's threat assessment is correct in pattern (rules are broken, OneAuth quarantine is real harm) but its identification of *the* critical event was wrong because the brief gave numbers from an outdated snapshot. The Antigravity finding is, ironically, one of the few **legitimate detections** in the dataset — an unsigned binary running from `%TEMP%` is exactly what the Authenticode rule should catch, even though the binary itself is benign.

---

## Prioritized Improvement Backlog

### P0 — fix this week (safety + correctness)

1. **Restore the OneAuth file.** Move `quarantine/1776569405_3c90aeba5d2b8121_75030987-cf12-46ac-b181-64136c14097d` back to `C:\Users\bradl\AppData\Local\Microsoft\OneAuth\accounts\75030987-cf12-46ac-b181-64136c14097d`. Verify Azure AD / MSA SSO still works.
2. **Disable or rewrite the four broken YARA rules** in `aegis/detection/yara_scanner.py` (`credential_harvester`, `cryptominer_strings`, `ransomware_note`, `data_exfil_tool`) and `rules/yara/custom_threats.yar`. Either tighten conditions to require PE/ELF magic gates or move heuristics out of YARA. Until then, these net-negative rules should not auto-trigger `quarantine_file`.
3. **Add a quarantine path allow-list** in `config/aegis.yaml` blocking quarantine of `%LOCALAPPDATA%\Microsoft\OneAuth\`, `%LOCALAPPDATA%\Microsoft\Windows\Notifications\`, `%LOCALAPPDATA%\Google\Chrome\User Data\`, `%LOCALAPPDATA%\Microsoft\OneDrive\`, and Outlook `.ost`/`.pst` paths. Defense-in-depth even after rule fixes.
4. **Add `purge_forensics()` rotation** mirroring `purge_case()` (`aegis/response/purge.py` already untracked-new — extend it). Default `forensics.retention_s = 30 days`. Wire into the scheduled response chain.
5. **Drop anomaly severity from `high` → `medium`** (or `low`) for Isolation Forest events. Set `auto_respond=false` for anomaly-only triggers. With `contamination=0.01` calibrated as 1% expected FP rate, every anomaly is by definition expected behavior.
6. **Anomaly-storm circuit breaker.** When `detection.anomaly` exceeds N/min for M consecutive minutes, suppress the response chain and emit a single `system.health` event. Token-bucket on `EventBus`. The Apr 18 storm would have been capped at 120/hr instead of 1,300+/hr.

### P1 — fix this month (signal quality + Windows coverage)

7. **Re-enable Sigma loader** (`detection.sigma.enabled: true`) and bundle a small SigmaHQ `process_creation` ruleset under `rules/sigma/`. Ships Windows behavioral coverage that doesn't exist today.
8. **Add Windows LOLBin patterns** to `aegis/monitors/process_mon.SUSPICIOUS_PATTERNS`: `powershell -enc`/`-EncodedCommand`, `rundll32 ...,*`, `mshta http`, `regsvr32 /s /n /u /i:`, `wmic process call create`, `bitsadmin /transfer`, `certutil -urlcache -decode`, `Add-MpPreference -ExclusionPath`, parent in `winword|excel|outlook` spawning child `cmd|powershell` (T1566 follow-on).
9. **Threat-intel staleness alert.** When `time.time() - cache.saved_at > 2 * refresh_seconds`, emit a `system.health` event. Today the silent failure mode is invisible.
10. **Persistence-baseline daily refresh.** Currently frozen since Apr 18 — 6 days of drift blindness.
11. **Force `--build-manifest` on every clean restart** and broaden coverage to `aegis/detection/*.py` and `aegis/monitors/*.py`. Set `self_protect.strict: true` once coverage is right.
12. **Test-suite guard against live DB.** `tests/test_step*.py` should refuse to run if `data/aegis.pid` mtime is fresh (<5 min). The lockfile catches the AEGIS process; nothing catches a test process opening the same DB.

### P2 — next quarter (the strategic moves)

13. **Local LLM triage layer** (`aegis/detection/llm_triage.py`) subscribed to `response.alert`. ~5-8 dev-days. Single biggest UX leverage in the backlog.
14. **OCSF event-schema export** in `aegis/utils/alerting.py`. ~3-5 dev-days. Makes the hash-chained log a credible audit artifact in any SIEM.
15. **Honeytoken monitor** (`aegis/monitors/honey_mon.py`) using existing FIM infra. ~2-3 dev-days.
16. **AMSI integration** (Windows) via ctypes. Closes PowerShell/JScript/Office-macro blind spot. ~5-8 dev-days.
17. **Cases view + SSE on the dashboard.** Replace polling with `StreamingResponse`; add `/cases/{id}` joining events on `case_id`. ~4-5 dev-days.
18. **Process Mitigation Policies** on Aegis bootstrap (`SetProcessMitigationPolicy` via ctypes). ~0.5-1 dev-day.

### P3 — Phase 2 (positioning-dependent)

- eBPF Linux telemetry (only after positioning is settled — Linux-side equivalent of AMSI/ETW)
- TPM-sealed manifest (depends on committing to "audit-grade" positioning)
- SBOM emission (CycloneDX) for the host
- Pydantic-typed config

**Phase 1 (P0+P1+top P2): ~30-40 dev-days** — a tight, defensible quarter.

---

## Top 3 New-Tech Adoption Recommendations

| # | Tech | Effort | Risk | Strategic value |
|---|---|---|---|---|
| 1 | **Local LLM (3-8B) for alert triage** | 5-8 dev-days | Low — runs offline, no PII egress | Turns severity stream into case stories. Pairs with OCSF export to ship human-readable enrichment to any SIEM. |
| 2 | **OCSF event-schema mapping** | 3-5 dev-days | Low — schema is stable LF Project | Makes hash-chained log portable evidence; unlocks every commercial SIEM with zero per-vendor work. |
| 3 | **AMSI integration on Windows** | 5-8 dev-days | Medium — ctypes API is well-documented but fiddly | Closes PowerShell/JScript pre-execution blind spot — the largest single Windows visibility gap in the project today. |

R&D's recommendation to **defer the kernel-driver/multi-host/syscall-ML directions** is correct — those are CrowdStrike-rebuild scope and not where Aegis wins.

---

## Holistic Project Review

### Right to win (R&D agent's framing, endorsed)

> Aegis is a transparent, auditable, single-host EDR for environments where black-box cloud EDR is not an option: classified/air-gapped hosts, research labs, teaching environments, OT/ICS jump boxes, and security professionals who want to understand what their EDR is actually doing.

This positioning is real and defensible. CrowdStrike, SentinelOne, MDE actively avoid it (it conflicts with their cloud-telemetry business model). Wazuh occupies adjacent SIEM/agent-manager territory but is not response-chained or hash-chain-audited.

### Double down on
- Hash-chained event log + `verify_chain()` (it works — proven this audit)
- 5-step response chain with `case_id` flowing through every artifact
- Manifest verification + self-protect (extend with TPM in Phase 2)
- MITRE ATT&CK Navigator coverage export (rare for OSS, audit-relevant)
- Sub-800-LoC-per-module readability — *this is the teaching/research differentiator*

### Cut / deprioritize
- "Compete with CrowdStrike" framing — sets wrong success criteria
- `network_mon.SUSPICIOUS_PORTS` static heuristic list (decade-old, FP-heavy — replace with TI-driven scoring or remove)
- Half-enabled Sigma loader — commit to it as first-class or drop entirely
- `EmailAlerter` — webhook covers the same need with less config burden
- macOS support — already implicitly out of scope; make it explicit
- Anomaly retrain knobs in YAML — auto-retrain weekly on a fixed schedule and remove the configurability

### Strategic decisions for the user
1. **Positioning commit.** Are you publicly committing to "audit-grade single-host research/teaching EDR"? Backlog above assumes yes. If you want "open-source CrowdStrike," eBPF + ETW + multi-host correlation move to top and LLM moves down.
2. **Local LLM model choice.** Phi-3.5-mini, Llama-3.2-3B-Instruct, Qwen-2.5-7B-Instruct are all plausible 2025-2026 candidates. Pick by benchmarking on a held-out set of Aegis events.
3. **Drop macOS explicitly.** Simplifies every downstream design decision.

---

## Open Questions

- **Why are `proc.create` events seeing 0 quarantine outcomes in the live DB despite the Antigravity installer being severity=critical with `auto_respond` likely on?** Either auto-respond is off for `procmon` source, or the response engine refused (path/PID gone). Worth checking `response.auto_respond` config + the engine logs.
- **Does FIM coverage actually include all the system paths it should?** baseline.db has 1.17M rows; spot-check whether `C:\ProgramData`, `C:\Windows\Temp`, all user `AppData\Roaming` are represented.
- **Forensics dir 95% from one storm** — were the storm's anomaly events actually triggered by anything material, or pure model thrash? A retrospective on those 10,652 captures could refine the IF feature set.

---

## Verification Status

- [x] Three reports exist, well-formed, cite event_ids/file paths/line numbers
- [x] Joint SWOT cells trace to evidence in domain reports + main-session SQL
- [x] Crash hypothesis confirmed (dual-writer split-brain, ~95% confidence) and recovery verified (chain intact, change_counter reset)
- [x] Hash chain integrity verified directly: 0 breaks across 32,791 events
- [x] R&D recommendations grounded in concrete code paths and effort estimates
- [x] Roadmap has evidence-tied P0s and value-tied P2s

The single most important action: **decide the positioning question.** Everything in the P2 backlog depends on it.
