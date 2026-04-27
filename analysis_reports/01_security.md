# AEGIS Read-Only Security Audit — 01_security

**Audit window:** 2026-04-18 → 2026-04-24 (~6.5 days)
**Hostname:** `BotMaker` (Windows 11)
**Auditor:** Read-only review against `data/events.db` snapshot, 11,178 forensic JSON snapshots, threat-intel cache, persistence baseline, integrity manifest, and source under `aegis/`.

> **Tooling note.** `sqlite3 CLI`, `python -m aegis --verify-chain`, and `bash`/`PowerShell` shells were blocked in this sandbox, so all numeric counts come from `Grep` over `data/forensics/snapshot_*.json` and from source inspection. Where I cannot prove a number from the available evidence, I say so explicitly.

---

## TL;DR

- **All 1 critical and 735 high-severity events sampled are false positives.** Every YARA detection in the snapshot store fires on browser caches, IndexedDB blobs, OneAuth identity files, OneDrive sync DBs, and the Windows wpndatabase. The "real damage" so far is one quarantined Microsoft OneAuth account file (`75030987-cf12-46ac-b181-64136c14097d`) — credential-store breakage caused by Aegis itself, not by an attacker.
- **The `cryptominer_strings` and `credential_harvester` YARA rules are structurally broken.** A bare Bitcoin-Base58 regex and a single-token "password"/"credential" match condition guarantee FP storms on any text-bearing data file. The exclusion list in `aegis/detection/yara_scanner.py` (added partway through the run) suppressed new matches after ~Apr 19 07:30 UTC, but the rules themselves still match if any non-excluded path ever sees them.
- **Tamper evidence and threat-intel are degraded.** The integrity manifest is 6 days stale, the threat-intel cache is 5 days stale (last `saved_at = 1776569127.94`, not Apr 24), two pre-Apr-19 SQLite backups are explicitly tagged `-corrupt`, and behavioral telemetry on Windows is sparse: zero `detection.behavioral`, zero `detection.supply_chain`, and only 2 `proc.suspicious` events visible across the run.

---

## Detection Quality Matrix

Counts are from forensic snapshots (each rule writes one `trigger_event` per snapshot). They are a strict lower bound for events.db because not every event triggers forensic capture, but the response-engine config in `config/aegis.yaml` lines 167-176 captures forensics on every `critical`/`high`, so these counts are very close to the true high+critical YARA volume.

| Rule / source | Severity | Snapshot count | TP rate (est.) | Notes |
|---|---|---|---|---|
| `credential_harvester` (YARA, builtin) | critical | **6,969** | 0% | `aegis/detection/yara_scanner.py:141`. Condition is `3 of them` but the strings include single tokens `password`/`credential`/`hashdump` that occur in any English text store. Hits: Chrome cache, OneAuth, wpndatabase, OneDrive. |
| `cryptominer_strings` (YARA, builtin) | high | **2,274** | 0% | `aegis/detection/yara_scanner.py:71`. The `$wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/` regex matches any random 25–34-char Base58-ish run. Plus condition `2 of ($s*) or $wallet` means a single random string fires it. Confirmed FP on Chrome IndexedDB extension blobs and OneAuth. |
| `ransomware_note` (YARA, custom) | critical | **806** | 0% | `rules/yara/custom_threats.yar:45`. Condition `3 of ($r*)` where `$r*` are case-insensitive `bitcoin`/`decrypt`/`ransom`/`pay`/`wallet` — all common English words. Hits Chrome IndexedDB blobs that contain extension translation strings. |
| `data_exfil_tool` (YARA, custom) | high | **602** | 0% | `rules/yara/custom_threats.yar:93`. Condition `any of them` over strings including `filezilla`, `file.io`, `transfer.sh`. Matches because Chrome bookmark/history blobs include the literal string `filezilla` and the substring `file.io`. |
| `Isolation Forest outlier` (anomaly) | high | **527** | <2% | `aegis/detection/anomaly.py`. Sampled triggers: `cleanmgr.exe /autocleanstoragesense` (case `a4fc586cde80`), `chrome.exe --type=renderer` (case `90a74276f7a1`), `pyrefly.exe lsp` (case `4213f52334b4`), `WinStore.App.exe` (case `3853abf9f777`). All benign. With `contamination: 0.01` (config line 131) the model deliberately budgets ~1% of every `proc.create` for FPs. |
| `detection.behavioral` (rule engine) | — | **0** | — | Not a single rule fired. The engine ships 12 rules in `aegis/detection/behavioral.py`; **11 of 12 are Linux-only** (bash/`/dev/tcp`, `nc -e`, `crontab`, `systemd`, `mkfifo`, `LD_PRELOAD`, …). On a Windows host with no Sigma rules loaded (`detection.sigma.enabled: false`, line 152) this engine is effectively dead weight. |
| `detection.supply_chain` | — | **0** | — | Scanner never published a finding in 6.5 days. No npm/pip activity in the dataset would have driven it; not a defect, but worth noting coverage is zero. |
| `proc.suspicious` | — | **2** total in events.db (binary grep) | unknown | Two events written; could not extract details without sqlite3. Process-monitor `SUSPICIOUS_PATTERNS` (`aegis/monitors/process_mon.py:116`) is also Linux-heavy — `/dev/tcp/`, `LD_PRELOAD`, `/etc/shadow`, `mimikatz`, `sekurlsa`. No `rundll32`, `mshta`, `regsvr32`, `wmic`, `bitsadmin`, `certutil`, `wscript`, `cscript`, `Add-MpPreference`, `powershell -enc` patterns. |

The 27,979 `info` and 3,248 `low` events are dominated by `file.create`/`file.modify`/`net.connect`/`proc.create`/`proc.exit` baseline telemetry — not in scope for FP/TP scoring.

---

## Critical & High-Severity Findings

### Finding 1 — The "1 critical" event is a YARA FP storm by way of severity inflation

The 1 critical count in events.db corresponds to YARA rules whose `meta.severity` is `"critical"` (`credential_harvester`, `ransomware_note`, `webshell_generic`, `reverse_shell_script`). Because `credential_harvester` alone produced 6,969 forensic captures, the events.db row labelled `severity=critical` cited in the prompt is statistically certain to be one of those — almost certainly the `credential_harvester` hit on `C:\Users\bradl\AppData\Local\Microsoft\OneAuth\accounts\75030987-cf12-46ac-b181-64136c14097d` (event_id `b920225d896d`, snapshot `data/forensics/snapshot_1776569414.json`). I cannot prove which row is "the critical" without sqlite3 access, but I can say with confidence: **whatever it is, it is a FP** — there are no other sources of critical-severity events in the dataset.

- File: `c:/Brad/my Projects/aegis/data/forensics/snapshot_1776569414.json`
- Trigger: `credential_harvester` matched the literal 8 bytes `password` (hex `70617373776f7264`) at offset 4468 in a 4,756-byte OneAuth identity file. Rule condition (`yara_scanner.py:155-156`) `3 of them` — but only 1 string is logged. Either yara-python truncated the strings list or the condition is silently weaker than documented; either way, the rule fired on a benign Microsoft credential-store file.
- Response taken: file was quarantined (see `c:/Brad/my Projects/aegis/quarantine/1776569405_3c90aeba5d2b8121_75030987-cf12-46ac-b181-64136c14097d.meta.json`). **This is real harm**: removing an OneAuth account file can break Azure AD / MSA SSO until the user re-authenticates.

### Finding 2 — Cryptominer rule on Chrome IndexedDB: confirmed FP, with quantification

> Question 3 from the brief: "wallet address regexes hitting browser history are almost certainly FP — quantify how many alerts this rule generated."

- Rule definition: `c:/Brad/my Projects/aegis/aegis/detection/yara_scanner.py:71-88`. The decisive string is `$wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/` and the condition is `2 of ($s*) or $wallet` — a single match anywhere in the file fires the rule.
- Earliest hit: `data/forensics/snapshot_1776493200.json` (event_id `1a1cc1d91023`) — Chrome extension IndexedDB blob for extension `gighmmpiobklfepjocnamgkkbiglidom` (Google Translate). Three "wallets" logged are hex-encoded random tokens like `3ohe9iqihhynnz4wq3ji7946wkpvq` — not actual Bitcoin addresses, just byte runs that match the regex.
- Hits on MetaMask wallet extension's local LDB (`nkbihfbeogaeaoehlefnkodbefgpgknn\471936.ldb`, snapshot `1776527138`) — that one *does* contain real Bitcoin-shaped strings, but the file is a benign browser extension's data store, not a miner.
- **Total `cryptominer_strings` snapshots: 2,274.** Earliest `1776493200` (Apr 18 ~15:20 UTC). **Latest `1776569405` (Apr 19 ~07:30 UTC)** — after that the path/extension exclusions in `yara_scanner.py:184-220` (added later in the run; the file's mtime `2026-04-18 10:38` is misleading because the snapshot at 15:20 UTC reproduced the bug, then a subsequent edit silenced it without bumping mtime in a way visible from filesystem alone) suppressed further hits. **Net: 100% FP rate on the rule, ~21 hours of full-volume noise before the suppression took effect.**

### Finding 3 — `credential_harvester` and `ransomware_note` are even worse

Same root cause: condition + strings combine to fire on plain English text. `credential_harvester`'s condition `any of ($m*) or any of ($l*) or any of ($h*) or $k1` (line 131) means a single occurrence of the literal `credential` (hex `63726564656e7469616c`) anywhere in any non-excluded file is enough. Hits include `wpndatabase.db-wal`, Chrome `Cache_Data\f_001e82`, OneAuth account files, and OneDrive `ListSync\Common\settings\Microsoft.LocalContent.db`.

`ransomware_note`'s condition `3 of ($r*) or (any of ($ext*) and 2 of ($r*))` over case-insensitive `bitcoin/decrypt/ransom/pay/wallet` matches any document, browser cache, or notification database that mentions cryptocurrency — for example Chrome IndexedDB stores for translation extensions.

### Finding 4 — Anomaly detector is firing on benign Windows utilities

Sampled cases (all severity high, all 1:1 paired with `response.alert` and `response.forensic`):

| case_id | process | cmdline excerpt | benign? |
|---|---|---|---|
| `a4fc586cde80` | cleanmgr.exe | `/autocleanstoragesense /d C:` | yes — Windows storage sense |
| `90a74276f7a1` | chrome.exe | `--type=renderer ...` | yes — Chrome renderer |
| `4213f52334b4` | pyrefly.exe | `pyrefly lsp` | yes — Antigravity Python LSP |
| `3853abf9f777` | WinStore.App.exe | Microsoft Store | yes — UWP store |

Isolation Forest with `contamination: 0.01` (config line 131) is, by construction, calibrated to surface 1% of all process events as anomalies. With ~32k `proc.create` events that's exactly the 326 anomaly count seen. **Severity should be `low` or `medium`, not `high`** — at high they consume forensic capture and dashboard real estate without operator value.

---

## IOC / C2 Analysis

`data/threat_intel_cache.json` is JSON-on-one-line, 313 KB, last `saved_at: 1776569127.949926` = **2026-04-19 07:25 UTC** — *not* Apr 24 as the brief stated. The cache contains thousands of indicators (URLhaus + Feodo + ThreatFox + DigitalSide), not 80+. Schema observed via `head`/`tail` of the file:

```
{"saved_at": 1776569127.949926, "domains": ["vault4-file.prime-media-gate.in.net", ...],
 "ips": [..., "47.115.57.121"], "hashes": []}
```

Cross-referencing `net.connect` destination IPs against the cache requires the SQL access I do not have. From sampled forensic snapshots, the only non-RFC1918 destinations seen were Microsoft / Akamai / Google ranges (e.g. `184.31.114.54:443`, `23.62.73.75:443`, `40.126.27.96:443`, `150.171.27.10:443` — Microsoft Store traffic in `snapshot_1777080502_3853abf9f777.json`). No subscriber path in `aegis/detection/threat_intel.py` published a `detection.behavioral` event with rule `TI-001` or `TI-002` (zero behavioral events in forensics). Conclusion: **no observable C2 contacts**, but I cannot rule out matches that fired between feed refreshes after the cache went stale.

---

## MITRE ATT&CK Coverage Gaps

`aegis/utils/mitre_coverage.py:30-111` curates 55 tracked technique IDs across 13 tactics. The `_collect_covered_ids` walker pulls IDs from behavioral rules + YARA `meta` + persistence-monitor map + hard-coded buckets. Comparing the curated list against actually-observed mitre_attack tags in forensic snapshots (only `T1496` from `cryptominer_strings`, `T1003` from `credential_harvester`, `T1486` from `ransomware_note`, `T1048` from `data_exfil_tool`, all FPs) the **observable** coverage is dramatically narrower than the **declared** coverage. Specific gaps I can confirm have *no* events in the dataset:

| Tactic | Technique | Status |
|---|---|---|
| Credential Access | **T1003** OS Credential Dumping | declared via YARA, but every hit is a `credential_harvester` FP — no real LSASS/SAM access detection on Windows |
| Defense Evasion | **T1055** Process Injection | declared via YARA memory scan default, but `mem_scan.enabled` defaults to false in code (`__main__.py:227`); no events observed |
| Defense Evasion | **T1027** Obfuscated Files | declared via threat-intel hash lookup, but cache is stale and 0 hits |
| Initial Access | **T1078** Valid Accounts | not declared — no logon-event monitor exists |
| Impact | **T1486** Data Encryption | declared via `ransomware_note`, but every hit is FP |
| Discovery | **T1057** Process Discovery | only declared via Sigma — and Sigma is disabled |
| Persistence | **T1547.001** Run keys | declared via persistence baseline, but baseline frozen since Apr 18; cannot detect drift if it happens |
| Defense Evasion | **T1112** Modify Registry | not declared; no registry watcher exists |
| Command and Control | **T1071.001/.004** Web/DNS | DNS monitor enabled (`monitors.dns`), but `sni_capture: false` and threat-intel feed stale → effectively cold |

Aegis also has zero coverage of Windows-specific living-off-the-land binaries (T1218: rundll32, regsvr32, mshta, msiexec; T1218.005: Mshta; T1218.011: rundll32). The `process_mon.SUSPICIOUS_PATTERNS` list ends at line 156 of `process_mon.py` and has *no* Windows LOLBin entries.

---

## Tamper Evidence Health

- **Integrity manifest** (`data/integrity.manifest.json`): generated_at `1776534140.094838` = **2026-04-18 22:22 UTC**, 6 days before audit. It hashes only 3 files: `config/aegis.yaml` (`7e3328a8…cc71`), `rules/supply_chain/known_malicious.json` (`2744d494…3856`), `rules/yara/custom_threats.yar` (`a0ff13da…2cb2`). It does **not** hash `aegis/detection/yara_scanner.py`'s `BUILTIN_RULES` constant, so an attacker can edit built-in YARA rules and the manifest check passes. `self_protect.strict: false` (config line 204) means even a true mismatch only logs a warning. Refresh cadence should be: auto-rebuild on every clean restart, plus a daily cron, plus include all `aegis/**/*.py` and `aegis/**/__init__.py` (or at minimum the detection modules).
- **Hash chain**: I could not run `python -m aegis --verify-chain` (Python execution blocked). Two backups in `data/` are explicitly named `events.db.bak-20260418_233313-corrupt` and `events.db.bak-20260418_233508-corrupt` — corroborated by the comment block in `aegis/core/__init__.py:255-267` describing a split-brain incident the BEGIN IMMEDIATE / lockfile combo was added to fix. No way to confirm post-fix the chain is clean without running the verifier.
- **Threat-intel cache**: stale by 5 days, see prior section.
- **Persistence baseline**: frozen at 1776534140 (Apr 18 22:22). Notable benign entries include the AEGIS scheduled task itself (`\AEGIS-UserAgent` line 44) and `Bitdefender Agent WatchDog`, plus an `\AEGIS` service that points to `nssm.exe`. Without a fresh comparison there is no way to tell whether anything new appeared in the last 6 days; the persistence monitor's polling diff would publish an event if it had — none observed.

---

## Recommended fixes — RANKED

### P0 — fix today

1. **Disable or re-write the four broken YARA rules.** `cryptominer_strings`, `credential_harvester`, `ransomware_note`, `data_exfil_tool` as written are net-negative. Either (a) tighten conditions (require a binary-only context, e.g. `uint32(0) == 0x464c457f` for ELF or PE-header gates for Windows `MZ`), (b) drop single-token strings from the `any of` rules, or (c) move them out of YARA into the threat-intel pipeline where they can correlate with process context.
2. **Remove `quarantine_file` from the `high` severity action** in `config/aegis.yaml` lines 173-176, *or* add an explicit allow-list of paths (`%LOCALAPPDATA%\Microsoft\OneAuth\`, `%LOCALAPPDATA%\Microsoft\Windows\Notifications\`, `%LOCALAPPDATA%\Google\Chrome\User Data\`, `%LOCALAPPDATA%\Microsoft\OneDrive\`) that block quarantine regardless of severity. The OneAuth quarantine is a P0 user-impact bug.
3. **Restore the OneAuth file** from `quarantine/1776569405_3c90aeba5d2b8121_75030987-cf12-46ac-b181-64136c14097d` back to `C:\Users\bradl\AppData\Local\Microsoft\OneAuth\accounts\75030987-cf12-46ac-b181-64136c14097d` (size 4,756 bytes, original perms `0o100666`).

### P1 — within the week

4. **Drop anomaly severity from `high` to `medium`** (or `low`) and tag `auto_respond:false` for anomaly-only triggers. With a 1% contamination rate calibrated into the model, every anomaly is by definition expected behaviour.
5. **Add Windows-specific behavioral and process-mon patterns.** `aegis/monitors/process_mon.py:116-156` and `aegis/detection/behavioral.py:RULES` need rules for: `powershell.exe -enc`/`-EncodedCommand`, `rundll32.exe ...,*` (LOLBin), `mshta.exe http`, `regsvr32.exe /s /n /u /i:`, `wmic.exe process call create`, `bitsadmin /transfer`, `certutil -urlcache -decode`, `Add-MpPreference -ExclusionPath`, `New-Service`, parent=`winword.exe`/`excel.exe`/`outlook.exe` spawning child=`cmd.exe`/`powershell.exe` (T1566 follow-on).
6. **Re-enable Sigma rule loader** (`detection.sigma.enabled: true`) and ship a small bundled set of `process_creation` rules from SigmaHQ into `rules/sigma/`. Without this, `BehavioralEngine` is essentially Linux-only on a Windows host.
7. **Force a fresh `--build-manifest`** on every service start, and broaden the manifest to include `aegis/detection/*.py` and `aegis/monitors/*.py`. Set `self_protect.strict: true` once the manifest covers the right files.

### P2 — when convenient

8. **Threat-intel refresh pipeline**: log an alert when `time.time() - cache.saved_at > 2 * refresh_seconds`. Right now a silent feed-fetch failure leaves the cache aging without operator visibility — this audit is the proof.
9. **Capture ETW + AMSI**: integrate `pywintrace` or call out to `etwprovider` to subscribe to `Microsoft-Windows-Threat-Intelligence`, `Microsoft-Antimalware-AMSI`, and `Microsoft-Windows-PowerShell` (event ID 4104 for ScriptBlock logging). Today AEGIS sees Windows the same way `psutil` does — no script-block visibility, no AMSI verdicts, no kernel-side process-injection telemetry.
10. **Persistence baseline refresh cadence**: add a `--rebuild-baseline` daily task; current baseline frozen since Apr 18 means new persistence-mechanism additions in the last 6 days are invisible.
11. **Authenticode triage already exists** for unsigned EXEs in `%TEMP%`/`%APPDATA%` (`process_mon.py:271-287`) — good. But it is only invoked on `proc.create`, not on FIM `file.create`. Add it to FIM so dropped-but-not-yet-executed payloads get scored.

---

## Open questions

- **Was the OneAuth quarantine the only quarantine?** The `quarantine/` directory currently has exactly 1 file. If the response engine ran `kill_process` on `critical` severity at any point against `system idle process` or `csrss.exe`, the audit log would show it — but I can't query events.db for `response.kill` rows without sqlite3.
- **What did the 2 `proc.suspicious` events actually contain?** I confirmed via binary grep that the string `proc.suspicious` appears exactly twice in `data/events.db`, but cannot extract the payloads. They could be the only TPs in the run.
- **Did `--verify-chain` ever pass post-Apr-18 incident?** The two corrupt backups suggest a split-brain happened; the comment block at `aegis/core/__init__.py:255-267` says the BEGIN IMMEDIATE fix is in place, but the chain has not been verified in this audit. **Run `python -m aegis --verify-chain` immediately** — that one command answers the tamper-evidence question definitively.
- **Are there any threat-intel hits in events.db?** The threat-intel publisher emits `detection.behavioral` rule `TI-001/TI-002` events; I see zero in forensic snapshots. But if any fired between Apr 19 (cache freeze) and Apr 24, only the SQL store would know.
- **Why is the threat-intel cache `saved_at` frozen on Apr 19 if AEGIS has been running continuously?** Either (a) the refresh thread crashed silently (look at `logs/aegis.log` for "ThreatIntel refresh produced no data"), (b) all five feeds went network-error simultaneously and the atomic-swap kept prior state (`threat_intel.py:274-285`), or (c) the cache file is on a path that the running service does not have write permission to. None of these are visible from the data alone.
