# AEGIS Agent Skills

Specialized agent personas for the AEGIS codebase. Each `.md` file is a self-contained
CLAUDE.md that can be loaded as context for a focused agent session.

## Usage

Point Claude Code (or any agentic harness) at one of these files as the system prompt
or CLAUDE.md override. The agent receives:

1. **Identity & mandate** — who they are, what they own, what they refuse.
2. **Pre-digested context** — architecture summary, file map scoped to their domain,
   event-bus topology, config keys they care about. No need to re-read 50+ source files.
3. **Behavioral directives** — Karpathy-style do/don't lists tuned to the persona.
4. **Verification protocol** — how the agent proves its work before reporting done.

## Agents

| File | Persona | Domain |
|------|---------|--------|
| `security.md` | **Red/Blue Security Engineer** | Threat modeling, detection gaps, rule authoring, evasion analysis, MITRE coverage |
| `test.md` | **Test Engineer** | Test suite health, coverage gaps, regression tests, integration tests |
| `qa.md` | **QA / Reliability Engineer** | Config validation, false-positive tuning, operational health, log hygiene |
| `rnd.md` | **R&D / Architecture** | New capabilities, ML pipeline, performance, integration design |
| `ops.md` | **DevOps / Deployment** | Install scripts, service lifecycle, self-protection, platform compat |
| `detection.md` | **Detection Engineer** | YARA rules, Sigma rules, behavioral rules, anomaly tuning, threat-intel feeds |

## Design Principles

- **Context efficiency**: Each agent carries enough project context to begin working
  immediately. No "read the whole codebase first" phase.
- **Minimal overlap**: Agents own distinct file sets. Cross-cutting concerns name the
  responsible agent explicitly.
- **Verification-first**: Every agent has a "prove it works" section. No agent reports
  done without running its verification step.
- **Safe by default**: Agents that touch response/quarantine logic must check the
  allow-list. Agents that touch detection must check false-positive rate.
