# How Modern Antivirus & Endpoint Security Actually Works

## From Kernel to Cloud — A Complete Technical Reference

> Synthesized from 40+ sources: peer-reviewed papers, industry whitepapers, vendor research, and open-source project architectures. This document captures the full body of knowledge needed to understand, build, evaluate, and break modern endpoint security systems.

---

## Table of Contents

1. [The Fundamental Problem](#1-the-fundamental-problem)
2. [The Privilege Layer Stack](#2-the-privilege-layer-stack)
3. [Kernel-Mode Mechanisms (Ring 0)](#3-kernel-mode-mechanisms-ring-0)
4. [User-Mode Detection (Ring 3)](#4-user-mode-detection-ring-3)
5. [The Detection Pipeline](#5-the-detection-pipeline)
6. [Signature-Based Detection](#6-signature-based-detection)
7. [Behavioral Detection](#7-behavioral-detection)
8. [Machine Learning in Malware Detection](#8-machine-learning-in-malware-detection)
9. [AMSI — The Fileless Threat Game-Changer](#9-amsi--the-fileless-threat-game-changer)
10. [ETW — Event Tracing for Windows](#10-etw--event-tracing-for-windows)
11. [EDR vs Traditional AV](#11-edr-vs-traditional-av)
12. [Cloud Intelligence Layer](#12-cloud-intelligence-layer)
13. [Detection Rule Frameworks](#13-detection-rule-frameworks)
14. [Evasion Techniques & Why They Matter](#14-evasion-techniques--why-they-matter)
15. [Open-Source Security Projects — What to Learn From Each](#15-open-source-security-projects--what-to-learn-from-each)
16. [Key Research Papers & Sources](#16-key-research-papers--sources)
17. [Unsolved Problems & Active Research](#17-unsolved-problems--active-research)

---

## 1. The Fundamental Problem

Malware detection is fundamentally an adversarial classification problem. The defender must decide, for every file written, process created, and script executed, whether the action is benign or malicious — in real time, with minimal false positives, and against an adversary who is actively adapting.

The challenge is asymmetric: the defender must catch everything; the attacker only needs to slip through once.

AV-TEST Institute reports that by May 2024, there were 49.5 million newly discovered malware samples, with over 85% targeting Windows and nearly 90% targeting executable (PE) files. The volume makes purely manual analysis impossible — automation, heuristics, and ML are not optional, they're required.

The evolution has been: signature matching (1990s) → heuristic analysis (2000s) → behavioral monitoring (2010s) → ML/cloud hybrid (2020s) → XDR with cross-endpoint correlation (current). Each generation didn't replace the previous — it layered on top. Modern systems run all of these simultaneously.

---

## 2. The Privilege Layer Stack

Modern endpoint security operates across every privilege level simultaneously. Each layer provides visibility the others cannot. This is the most important conceptual foundation.

### Ring -1: Hypervisor / Firmware

The deepest trust boundary. Hardware-based attestation and Virtualization-Based Security (VBS) operate below the kernel. Microsoft's Windows Defender System Guard uses runtime attestation with an "assertion engine" that continuously measures kernel integrity from a hypervisor-isolated environment. Even a fully compromised kernel cannot hide from these measurements.

Key technologies:
- **VBS (Virtualization-Based Security):** Creates an isolated virtual mode for security-critical code
- **HVCI (Hypervisor-Protected Code Integrity):** Prevents unsigned code execution in kernel memory
- **Secure Boot + ELAM:** Early Launch Antimalware drivers load before any third-party driver (since Windows Server 2012)
- **TPM-backed Attestation:** Hardware root of trust for boot integrity

Why it matters: Trend Micro research found that the majority of kernel-level threats use signed drivers that have not been revoked, with some achieving zero detection across all engines. The hypervisor layer is the only vantage point that can reliably detect these.

### Ring 0: Kernel Mode

The kernel is described across security research as "the source of all truth." Data from user mode cannot be fully trusted because attackers with code execution can tamper with userland hooks. The kernel's callbacks and minifilters provide ground truth.

Modern AV/EDR uses a **thin kernel driver** for interception combined with **heavyweight user-mode engines** for analysis. This is deliberate: kernel code must be minimal, fast, and stable (bugs cause BSOD). Complex logic runs in user-mode or cloud.

### Ring 3: User Mode

Where the sophisticated detection logic operates: signature scanning, behavioral analytics, ML inference, AMSI integration, sandboxed emulation, and cloud lookups. Richer context (user profiles, network stacks, scripting engines) enables more sophisticated analysis than is possible in kernel mode.

### Cloud Layer

Telemetry flows to cloud backends where large-scale ML models, threat intelligence graphs, and cross-endpoint correlation operate. CrowdStrike's architecture uses a graph database tracking relationships between endpoint events across millions of sensors. This is the "hive mind" advantage.

---

## 3. Kernel-Mode Mechanisms (Ring 0)

### Minifilter Drivers

Minifilters register with the Filter Manager (fltmgr.sys) rather than attaching directly to the filesystem stack. The Filter Manager handles I/O request interception and provides a simpler programming model.

Each minifilter registers an `FLT_OPERATION_REGISTRATION` array specifying which I/O operations it wants pre- and post-operation callbacks for:

- **IRP_MJ_CREATE:** File open — scan on access, enforce policy
- **IRP_MJ_WRITE:** Data written — detect payload drops, ransomware encryption
- **IRP_MJ_SET_INFORMATION:** Metadata changes — detect timestomping
- **IRP_MJ_CLOSE:** Handle closed — trigger post-write scan

Reference: Matt Hand's "Evading EDR" (No Starch Press, Chapter 6) provides the most detailed public documentation of minifilter architecture in EDR products.

### Kernel Callbacks

- **PsSetCreateProcessNotifyRoutine:** Notified on every process creation/termination. This is how EDRs inject monitoring DLLs and track process lineage trees
- **ObRegisterCallbacks:** Intercept handle operations. Used for self-protection — stripping PROCESS_VM_WRITE and PROCESS_TERMINATE from handles to protected processes
- **PsSetLoadImageNotifyRoutine:** Triggered on DLL/EXE mapping into memory. Allows scanning every binary before execution
- **CmRegisterCallbackEx:** Registry modification monitoring — critical for persistence detection

### ETW Threat Intelligence (ETW-TI)

A protected kernel-mode ETW provider (`Microsoft-Windows-Threat-Intelligence`) accessible only to PPL (Protected Process Light) processes. Unlike userland hooks that can be patched, ETW-TI telemetry is generated from within the kernel itself. To access it, a vendor must have their driver signed by Microsoft with a special ELAM certificate, and their service must run as PPL.

ETW-TI provides events for: memory allocation, virtual memory protection changes, syscall patterns, and more. This is where the industry is heading — away from fragile userland hooks toward kernel-originated telemetry.

### Creative Hooking Techniques

Research by Denis (the-deniss.github.io, December 2022) documented how Avast implements syscall interception in Windows 11 22H2. Since traditional SSDT hooking is blocked by PatchGuard, Avast exploits the ETW infrastructure — replacing function pointers in the `HalpPerformanceCounter` structure used by the Circular Kernel Context Logger. This allows intercepting `PerfInfoLogSysCallEntry` and redirecting syscall handlers.

This demonstrates how AV vendors innovate within (and around) kernel protection mechanisms.

---

## 4. User-Mode Detection (Ring 3)

### DLL Injection & API Hooking

EDRs inject monitoring DLLs into processes and hook critical APIs (VirtualAllocEx, NtWriteVirtualMemory, CreateRemoteThread, etc.) using IAT hooking or inline hooking. The injected DLL intercepts API calls before they reach the kernel, allowing inspection of parameters and payloads.

However, since the hook lives in the same address space as the monitored process, it can be unhooked by the attacker. Techniques include:
- Reading clean ntdll.dll from disk and remapping it
- Direct syscall invocation (bypassing the hooked stubs)
- Hardware breakpoint-based "patchless patching"
- Thread stack spoofing to hide call chains

This is why the industry is shifting toward kernel-originated telemetry (callbacks, ETW-TI) as the authoritative signal, using userland hooks as supplementary data.

### Process Instrumentation Callback (PIC)

An undocumented Windows feature that can trace API calls. Unlike kernel callbacks, PIC runs in the process's address space, making it removable via `NtSetInformationProcess`. This is a supplementary data source, not a primary one.

---

## 5. The Detection Pipeline

When a file is written, a process created, or a script executed, it triggers a cascade of analysis stages:

1. **Interception:** Kernel minifilter or callback fires. I/O can be held pending while analysis occurs.
2. **Static Analysis:** Signature engine matches against known patterns (YARA rules, byte sequences, PE header anomalies, import table analysis). Fast — catches known threats in microseconds.
3. **Heuristic/ML Pre-filter:** Lightweight on-device ML model evaluates features (section entropy, import hash, file size ratios, packer signatures).
4. **Cloud Verdict:** Hash + metadata sent to cloud. Unknown files may be detonated in cloud sandboxes. Deep neural networks process raw bytes or image representations.
5. **Behavioral Monitoring:** If allowed to execute, API calls, registry modifications, network connections, and child process creation are monitored against behavioral rules.
6. **Response:** Quarantine, kill, isolate, or alert. EDR can roll back filesystem changes (anti-ransomware). Forensic data preserved.

Research demonstrates that hybrid pipelines combining static + dynamic + network-layer analytics achieve approximately 92% detection rates with 3.5% false positive rates, versus 34% for traditional AV alone (ResearchGate, 2024).

---

## 6. Signature-Based Detection

### How It Works

The simplest and oldest technique. A database of known-bad patterns (signatures) is compared against files and memory. When a match is found, the file is flagged.

Signatures can be:
- Cryptographic hashes (exact match — trivially evaded by changing one byte)
- Fuzzy hashes (ssdeep, sdhash — tolerate minor modifications)
- Byte patterns with wildcards (YARA-style)
- Import hash (imphash — matches on the import table structure)

### Strengths

- Extremely fast (microsecond matching)
- Near-zero false positives on known threats
- Easy to update (just add new signatures)
- Works offline (no cloud required)

### Weaknesses

- Cannot detect unknown (zero-day) threats
- Trivially evaded by polymorphic/metamorphic malware
- Database grows continuously (AV-TEST: 1.5 billion known samples)
- Requires continuous updates

### ClamAV Architecture (Open Source Reference)

ClamAV is the canonical open-source signature engine. Its architecture includes:
- Signature database format (CLD/CVD) with bytecode signatures
- PE unpacking engine for packed binaries
- Archive handler (ZIP, RAR, 7z, etc.)
- Heuristic analysis for common patterns
- Phishing detection subsystem

---

## 7. Behavioral Detection

### The Paradigm Shift

Instead of asking "what does this file look like?" behavioral detection asks "what does this program do?" This catches threats that signatures miss — polymorphic malware changes its appearance but must still perform the same malicious actions.

### What Gets Monitored

- Process creation chains (parent→child relationships)
- API call sequences (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread = process injection)
- File system operations (mass encryption = ransomware)
- Registry modifications (Run keys = persistence)
- Network connections (beaconing patterns = C2)
- Script content at runtime (via AMSI)

### Sigma Rules

Sigma is the generic detection rule format for SIEM/EDR behavioral detection. Written in YAML, rules translate to platform-specific queries (Splunk, Elastic, Sentinel, etc.). The community repository contains thousands of rules mapped to MITRE ATT&CK.

Example detection logic:
- Process "powershell.exe" with command line containing "-enc" → Potential encoded command execution (T1059.001)
- Process accessing lsass.exe with GrantedAccess 0x10 → Credential dumping (T1003)

### Indicators of Attack (IOA) vs Indicators of Compromise (IOC)

- **IOCs** are artifacts: file hashes, IP addresses, domain names. They're retrospective — by the time you find them, the attack has happened.
- **IOAs** are behavior sequences: the pattern of actions that constitute an attack. They're predictive — you can detect the attack while it's in progress.

Modern EDR focuses on IOAs. CrowdStrike processes IOAs by understanding individual events as part of broader sequences. If a sequence matches a known attack pattern, it fires.

---

## 8. Machine Learning in Malware Detection

### Feature Extraction Approaches

**Static features** (extracted without executing the file):
- PE header fields (section count, entropy, size ratios)
- Import table analysis (API functions imported)
- String analysis (suspicious strings, obfuscation indicators)
- Byte n-grams (frequency of byte sequences)
- The EMBER dataset provides 2,381 features from 1.1M PE samples — the standard benchmark

**Dynamic features** (extracted during sandboxed execution):
- API call sequences
- Runtime parameters of API calls (semantically significant)
- File/registry/network operations
- Memory allocation patterns

**Visualization-based** (PE binary → image → CNN):
- Convert PE file bytes to RGB images
- Process with CNN architectures (ResNet, EfficientNet, custom)
- Research from Frontiers in Computing Science (2025) shows this effectively combines static and dynamic analysis advantages

### Model Performance

Key findings from multiple research papers:

- **Classic ML (XGBoost, Random Forest):** 93%+ accuracy on EMBER features. XGBoost consistently outperforms. Fast training, interpretable.
- **Simple ANNs:** 95.22% detection rate with just a 3-layer network (512→128→8 neurons, tanh activation) — outperformed all complex architectures on EMBER data (Connors & Sarkar, arXiv:2212.13988)
- **Deep CNNs on raw bytes (MalConv-style):** Effective for family classification but computationally expensive
- **Combined YARA + Sigma + EDR:** ~92% DR with 3.5% FPR (ResearchGate, 2024)

### The Concept Drift Problem

Multiple survey papers emphasize that models trained on historical malware degrade rapidly against novel threats. The ecosystem produces approximately 450,000 new variants daily. Effective systems must combine static models with behavioral analysis and continuous retraining. No single technique is sufficient.

### Adversarial ML

Adversarial attacks against PE malware classifiers face constraints: they must maintain file format validity, executability, and malicious functionality. This limits the attack surface but doesn't eliminate it. It remains an active research area.

---

## 9. AMSI — The Fileless Threat Game-Changer

### What It Is

The Antimalware Scan Interface (AMSI) is a vendor-agnostic Windows interface. When a scripting host prepares to execute content, it calls `AmsiScanBuffer()` with the fully de-obfuscated content. The registered AV provider evaluates the content and returns a verdict.

Before AMSI, attackers could layer encoding (Base64 → XOR → string concatenation) to hide their payloads from static scanning. AMSI sees the final, de-obfuscated content right before execution — making all layers of encoding irrelevant.

AMSI is described by Red Canary as "one of the most significant improvements in endpoint security optics."

### Integrated Components

- PowerShell (scripts, interactive commands, dynamic code evaluation)
- Windows Script Host (VBScript, JScript)
- VBA Macros (Office macro content)
- JavaScript/XLM (Microsoft 365 Apps)
- User Account Control (elevation requests)
- .NET Assembly Loading (reflection-loaded assemblies)
- WMI (script execution and persistence)

### How It Works Technically

1. `amsi.dll` is loaded into the process
2. Script host calls `AmsiScanBuffer()` or `AmsiScanString()` with content
3. AMSI forwards to the registered provider (e.g., Windows Defender)
4. Provider returns a verdict (clean, suspicious, malware, blocked)
5. Script host acts on the verdict (allow or block execution)

AMSI events are also published via the `Microsoft-Antimalware-Scan-Interface` ETW provider (event ID 1101), enabling defenders to build detections on AMSI scan content.

### Known Bypass Vectors

All documented and detectable with proper monitoring:
- Patching `amsi.dll` in-process memory (overwriting `AmsiScanBuffer` to return clean)
- Forcing `amsiInitFailed` (preventing AMSI initialization)
- DLL hijacking (placing a rogue `amsi.dll` in the process directory)
- Registry key removal (deleting the AMSI provider registration)
- PowerShell downgrade to v2 (which lacks AMSI integration)

---

## 10. ETW — Event Tracing for Windows

### Architecture

ETW is a kernel-level event tracing mechanism consisting of:
- **Providers:** Applications/drivers that generate events
- **Sessions:** Kernel objects that buffer events from providers
- **Controllers:** Applications that manage sessions (logman.exe is the built-in controller)
- **Consumers:** Applications that receive and process events

Over 1,000 providers exist on Windows 10. Each provider publishes events categorized by keywords, levels, and opcodes.

### Security-Critical Providers

- **Microsoft-Windows-Threat-Intelligence:** Protected provider for kernel-level security telemetry. Only accessible to PPL processes.
- **Microsoft-Antimalware-Scan-Interface:** AMSI scan events (content inspected, verdicts)
- **Microsoft-Windows-Security-Mitigations:** Exploit mitigation events (DEP, ASLR, CFG)
- **Microsoft-Windows-Kernel-Process:** Process lifecycle events
- **Microsoft-Windows-Kernel-File:** File system activity

### Why EDRs Are Moving to ETW

ETW-TI is kernel-originated telemetry that cannot be tampered with from user mode. Unlike userland hooks (which can be unhooked), ETW events are generated inside the kernel. Attackers need kernel-level code execution to tamper with ETW — a much higher bar.

The industry trend is: kernel callbacks + ETW-TI for authoritative signals, userland hooks as supplementary confirmation.

---

## 11. EDR vs Traditional AV

### Traditional Antivirus

- Primarily signature-based file scanning
- On-access scanning (scan files when opened/created)
- Scheduled full-system scans
- Basic heuristics
- Limited to known threats
- Standalone — no cross-endpoint visibility

### EDR (Endpoint Detection and Response)

Coined by Gartner's Anton Chuvakin: "records and stores endpoint-system-level behaviors, uses various data analytics techniques to detect suspicious system behavior, provides contextual information, blocks malicious activity, and provides remediation suggestions."

Key differentiators:
- Continuous endpoint telemetry recording
- Behavioral analytics (detect unknown threats)
- Cloud-based ML and threat intelligence
- Incident investigation and forensic capabilities
- Automated response (isolate host, kill process, rollback changes)
- Cross-endpoint correlation (detect lateral movement)
- Threat hunting capabilities

### XDR (Extended Detection and Response)

XDR extends EDR across network, email, cloud workloads, and identity systems. It correlates signals across all security layers, closing visibility gaps between previously siloed security tools.

---

## 12. Cloud Intelligence Layer

### What Happens in the Cloud

- **Reputation lookups:** File hashes, URLs, IPs checked against massive threat databases
- **Cloud ML models:** Larger, more accurate models than can run on-endpoint
- **Sandboxed detonation:** Unknown files executed in isolated cloud VMs
- **Cross-endpoint correlation:** Detect lateral movement and coordinated attacks across the fleet
- **Threat intelligence enrichment:** IOCs correlated with threat actor attribution

### Architecture Example: CrowdStrike Falcon

CrowdStrike uses a graph database that tracks relationships between endpoint events across millions of sensors. The "Threat Graph" enables:
- Attribution to known adversary groups
- Detection of attack patterns spanning multiple hosts
- Query results returning in under 5 seconds across 90 days of data

---

## 13. Detection Rule Frameworks

### YARA

Pattern-matching engine for file and memory scanning. Developed by Victor Manuel Alvarez (VirusTotal) in 2007. Rules define string patterns, byte sequences, and boolean conditions.

Key capabilities:
- Text and hex string matching with wildcards
- Regular expression support
- Boolean condition logic
- Module system (PE module, ELF module, math module)
- Performance-optimized atom extraction for efficient scanning

Used internally by CrowdStrike, SentinelOne, and most EDR platforms.

### Sigma

Generic SIEM detection rule format in YAML. Write once, translate to any SIEM query language (Splunk SPL, Elastic KQL, Microsoft KQL, etc.).

Focuses on behavioral detection in log data:
- Process creation events (command lines, parent-child relationships)
- Network connections
- Registry modifications
- File system operations

The SigmaHQ repository contains thousands of community-contributed rules mapped to MITRE ATT&CK.

### Suricata/Snort Rules

Network-layer signature matching for IDS/IPS. Detects:
- C2 communication patterns
- Exploitation attempts
- Data exfiltration
- Malware download activity
- Protocol anomalies

---

## 14. Evasion Techniques & Why They Matter

Understanding evasion is essential for building robust detection. Every evasion technique reveals a gap that detection must cover.

### Kernel-Level Evasion
- DKOM (Direct Kernel Object Manipulation): Modifying kernel structures to hide processes/drivers
- Direct syscall invocation: Bypassing hooked SSDT entries
- Hypervisor rootkits: Running below the OS
- Signed driver abuse: Using legitimately signed but vulnerable drivers

### User-Mode Evasion
- API unhooking: Remapping clean ntdll.dll to remove hooks
- Direct syscalls: Calling kernel via syscall instruction directly
- AMSI bypass: Patching amsi.dll in memory
- ETW patching: Disabling event generation
- Thread stack spoofing: Hiding malicious call stacks
- Process hollowing: Replacing legitimate process memory with malicious code
- DLL sideloading: Placing malicious DLLs in trusted application directories

### Why EDRs Survive Evasion

Each individual evasion technique can be detected. Unhooking creates anomalies (clean ntdll loaded from unusual path). AMSI bypass attempts trigger their own detections. The challenge for attackers is that they must evade multiple layers simultaneously, and each evasion attempt itself generates detectable artifacts.

---

## 15. Open-Source Security Projects — What to Learn From Each

### Wazuh (XDR/SIEM)
- Fork of OSSEC, GPLv2
- Agent-server architecture with central management
- File integrity monitoring, rootkit detection, log analysis
- Vulnerability detection via CVE correlation
- YARA and Sigma integration
- Suricata integration for NIDS
- **Learn:** Full-stack endpoint security architecture, rule engines, agent design, SIEM correlation

### YARA (Pattern Matching)
- By VirusTotal, Apache 2.0
- Industry-standard pattern matching for malware classification
- Module system for PE, ELF, math analysis
- Used by virtually every security vendor internally
- **Learn:** Rule writing, performance optimization, module development, integration patterns

### Suricata (Network IDS/IPS)
- Multi-threaded, high-performance network analysis
- Protocol parsing, file extraction, Lua scripting
- EVE JSON structured output for SIEM integration
- **Learn:** Network-layer detection, protocol analysis, rule writing, performance at scale

### ClamAV (Antivirus Engine)
- By Cisco Talos, GPLv2
- Canonical open-source signature engine
- Bytecode signatures, PE unpacking, archive handling
- **Learn:** Signature database format, scanning algorithms, PE parsing internals

### Osquery (Endpoint Visibility)
- By Facebook/Meta, Apache 2.0
- Turns OS into a relational database queryable with SQL
- Virtual tables for processes, connections, users, modules, hardware
- **Learn:** Endpoint data model, query-based detection, extension development

### Velociraptor (DFIR)
- VQL query language for hunt-at-scale forensics
- Live endpoint forensics and artifact collection
- **Learn:** Forensic data collection, hunt workflows, artifact engineering

### Sigma (Detection Rules)
- Generic SIEM detection format in YAML
- Converts to any SIEM query language
- Thousands of community rules mapped to ATT&CK
- **Learn:** Detection engineering, log source abstraction, ATT&CK mapping

### MISP (Threat Intelligence)
- Threat intelligence sharing platform
- STIX/TAXII standard support
- IOC lifecycle management
- **Learn:** Threat intelligence operations, IOC formats, sharing standards

### Cuckoo Sandbox (Dynamic Analysis)
- Automated malware analysis in isolated VMs
- API hooking for behavior capture
- Network traffic analysis
- **Learn:** Sandbox architecture, dynamic analysis, behavioral signature creation

### Security Onion (Network Security Monitoring)
- Complete NSM distribution bundling Suricata, Zeek, Elastic Stack
- Full packet capture + IDS + log analysis
- **Learn:** Integrated defense deployment, alert triage, network forensics

---

## 16. Key Research Papers & Sources

### Peer-Reviewed / Academic

- "Binary and multiclass malware classification of Windows PE using classic ML and DL" — Frontiers in Computing Science (2025)
- "Deep learning-powered malware detection in cyberspace: a contemporary review" — Frontiers in Physics (2024)
- "Application of deep learning in malware detection" — Journal of Big Data (2025)
- "A novel deep learning-based approach for malware detection" — Engineering Applications of AI (2024)
- "Assessing the Effectiveness of YARA Rules for Signature-Based Malware Detection" — arXiv:2111.13910 (2021)
- "Evolution of EDR in Cyber Security: A Comprehensive Review" — E3S Conferences (2024)
- "Real-Time EDR with Machine Learning Integration" — ResearchGate (2025)
- "A Survey of Recent Advances in Deep Learning Models for Detecting Malware" — ACM Computing Surveys (2024)
- "On Studying the Antivirus Behavior on Kernel Activities" — ResearchGate (2018)
- "Machine Learning for Detecting Malware in PE Files" — Connors & Sarkar, arXiv:2212.13988 (2022)
- "If It Looks Like a Rootkit: Critical Examination of Kernel-Level Anti-Cheat Systems" — Dorner et al. (2024)

### Industry Whitepapers & Vendor Research

- "An In-Depth Look at Windows Kernel Threats" — Trend Micro (Sherif Magdy)
- "Windows Defender System Guard runtime attestation" — Microsoft Security Blog
- "AMSI integration with Microsoft Defender for Endpoint" — Microsoft Learn
- "Detecting Windows AMSI Bypass Techniques" — Trend Micro
- "Better know a data source: AMSI" — Red Canary
- "Evading EDR" (Chapter 6: Minifilters) — Matt Hand, No Starch Press (2023)
- "What is EDR?" — CrowdStrike, Palo Alto Networks, Fortinet

### Technical Deep Dives

- "Hooking System Calls in Windows 11 22H2 like Avast Antivirus" — the-deniss.github.io (2022)
- "EDR: Detections, Bypasses and other Shenanigans" — FourCore (2022)
- "Evading ETW-Based Detections" — s4dbrd (2024)
- "ETW: Event Tracing for Windows: The Ultimate Guide for SOC Analysts" — Hackers Terminal (2025)
- "Event Tracing for Windows 101" — Red Team Notes / ired.team

---

## 17. Unsolved Problems & Active Research

### Concept Drift
Models trained on historical malware degrade against novel threats. The malware ecosystem produces ~450K new variants daily. Continuous retraining is necessary but expensive.

### Adversarial ML
Attackers can craft samples that evade ML classifiers while maintaining malicious functionality. PE format constraints limit the attack surface, but it remains an open problem.

### Explainability
Deep learning models achieve high accuracy but can't explain why a file is malicious. This matters for: analyst trust, legal proceedings, false positive investigation.

### Fileless and Living-off-the-Land
Attacks that use only legitimate system tools (PowerShell, WMI, certutil, mshta) leave no malware artifacts to scan. Detection must shift entirely to behavioral analysis.

### Supply Chain Attacks
Malicious code injected into legitimate packages (SolarWinds, npm, PyPI). Detection requires: package provenance verification, behavioral analysis during installation, and build pipeline security.

### Kernel-Level Threats with Valid Signatures
Trend Micro found most kernel threats use signed drivers that haven't been revoked, with some having zero detection. The industry relies on driver signing as a trust mechanism, but this trust can be abused through: stolen certificates, vulnerable drivers (BYOVD), and revocation delays.

### Performance vs Security Trade-off
Every security check adds latency. Deep scanning, emulation, and behavioral analysis are CPU/IO intensive. Real-world endpoint security must balance detection depth against system responsiveness.

---

*This document represents the synthesized knowledge from 40+ sources analyzed for the AEGIS project. It is designed to be complete enough that any security engineer — human or AI — can use it as a reference for understanding, building, or evaluating endpoint security systems.*
