# AEGIS — LLM Triage Benchmark

- Generated: 2026-04-26 01:13:54
- Sample source: events.db (case-tagged high-severity)
- DB path: data\events.db
- Sample size: 20 events

## Results

| Model | Parsed | Parse rate | Useful rate | Latency p50 | Latency p95 | Tok-out p50 | Confidence dist |
|---|---|---|---|---|---|---|---|
| phi-3.5-mini | 20/20 | 100% | 100% | 12759 ms | 30318 ms | 90 | suspicious:20 |
| qwen-2.5-3b | 20/20 | 100% | 100% | 8389 ms | 9963 ms | 80 | suspicious:1, very-likely-malicious:19 |
| llama-3.2-3b | 18/20 | 90% | 90% | 6095 ms | 10039 ms | 52 | likely-fp:1, suspicious:11, very-likely-malicious:6 |

## Recommendation

Pick the model with the highest **useful rate** that fits the target host's RAM. Use latency-p95 to set the max_tokens_out cap so the worst case stays under the operator's tolerance budget.

## Decision (2026-04-26): ship `qwen-2.5-3b` as the default

**Hardware envelope** — Ryzen 7 5825U, 21.8 GB RAM (8.9 GB free), no usable GPU. CPU-only inference, llama-cpp-python Q4_K_M.

**Why Qwen-2.5-3B-Instruct over Phi-3.5-mini-instruct (the original SWOT pick)**:

- **~50% lower median latency** — p50 8.4 s vs 12.8 s on identical 20-event sample.
- **More than 3× lower p95 latency** — 10.0 s vs 30.3 s. Tighter tail means the dashboard inspector pane never blocks operator triage on a slow case.
- **Same 100% parse + useful rate** — no reliability tradeoff for the speed.
- **Apache-2.0** vs Phi's MIT — both permissive but Apache's explicit patent grant is preferable for downstream redistribution.

**Why not Llama-3.2-3B (the speed champion at p50 6.1 s)**:

- 90% parse rate after the brace-elision fix landed — remaining 10% emit `"confidence": "high"` (not in our `likely-fp | suspicious | very-likely-malicious` enum). This is a model-prompt issue, not infrastructure.
- Best calibration of the three (uses all three labels meaningfully: 1 likely-fp, 11 suspicious, 6 very-likely-malicious on this sample) — but a 10% drop-rate on the ship default is too high.
- Worth keeping in the registry as the "fastest" pick for users who tolerate occasional schema misses.

**Caveats inherited by Qwen as default**:

- **Calibration skews high.** 19/20 events labeled `very-likely-malicious` on this sample. The model is over-confident; system prompt should add few-shot examples that show when `likely-fp` and `suspicious` are correct.
- **No host-binding.** Output is text — must remain advisory and never feed automated destructive actions (the prompt-injection threat from a poisoned event payload is real; an attacker could try to talk the model into "this is a Windows update").
- **Sample size is 20.** Statistically thin. The audit's open question #2 called for ~50; we ran 20 because the wall-clock for the Phi-3.5-mini pass alone is 6 minutes. Re-run with `--sample 50` once you've grown a richer event corpus.

**Tier ladder (config knob `detection.llm_triage.model`)**:

| Tier | Pick | When |
|---|---|---|
| Default | `qwen-2.5-3b` | Any host with ≥4 GB free RAM and ≥3 GB free disk — best speed/reliability balance |
| Speed | `llama-3.2-3b` | Latency-critical UX; tolerate ~10% schema misses |
| Conservative | `phi-3.5-mini` | Won't ever cry wolf — every event labeled "suspicious" |
| Beefier | `qwen-2.5-7b` | ≥8 GB free RAM; better reasoning, ~2× slower |
| Top shelf | `phi-4` | ≥12 GB free RAM; near-cloud quality, ~3× slower |

## Calibration follow-up (2026-04-26)

After the verdict above, the system prompt was extended with three
few-shot examples — one per confidence label — to address Qwen's
over-confidence (95% `very-likely-malicious` on the original run).
Same 20-event sample, same hardware, same model.

| Metric | Original prompt | Calibrated prompt |
|---|---|---|
| Parse rate | 100% | 100% |
| Useful rate | 100% | 100% |
| Latency p50 | 8.4 s | 7.4 s |
| Latency p95 | 10.0 s | 14.6 s |
| Tokens-out p50 | 80 | 62 |
| Confidence dist | `suspicious:1, very-likely-malicious:19` | `likely-fp:2, suspicious:1, very-likely-malicious:17` |

**Net effect — modest but real.** The model now uses all three
confidence labels (was two), is willing to label 10% of these
high-severity events as `likely-fp`, and produces shorter outputs.
The p95 latency regression (+46%) is the cost of the longer system
prompt — the first-token latency is dominated by prompt processing.

**Why the over-confidence persists**: the sample population is biased.
Every event in the benchmark is `severity: high` AND has a `case_id`
(meaning the response chain already fired) — i.e., the population is
genuinely skewed toward malicious by construction. A 17/20 hit on a
biased-malicious population is not necessarily over-calling.

**Next step for further calibration tuning** (not included in this
run): build a balanced held-out set drawn from across `info`/`low`/
`medium`/`high` severities so the model has the chance to be
discriminating. With only `high` + `case_id` samples, "everything is
malicious" is approximately the right answer.

## Sample parse failures

First three unparseable outputs per model — useful for tightening the system prompt or adjusting `max_tokens_out`.

### llama-3.2-3b

```
"confidence": "high", 
"summary": "A quarantined file with a known SHA256 hash was detected, indicating potential malware presence.", 
"next_steps": ["Verify the file's origin and purpose", "Scan the system for additional malware"]
---
"confidence": "high", 
"summary": "A quarantined file with a known SHA256 hash was detected, indicating potential malicious activity.", 
"next_steps": ["Investigate the quarantined file", "Verify the SHA256 hash against a known good database", "Monitor the system for further suspicious activity"]
---
```
