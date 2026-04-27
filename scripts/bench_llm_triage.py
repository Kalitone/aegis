"""
AEGIS — LLM Triage Benchmark Harness
=====================================
Pulls a held-out set of recent detection events from `data/events.db`
and runs each candidate model over the same prompts, producing a
comparison table:

  * latency (median, p95)
  * tokens out
  * parse-success rate
  * confidence-label distribution
  * any obvious failure modes (raw output dumped on parse failure)

Usage
-----
    python scripts/bench_llm_triage.py \
        --models phi-3.5-mini llama-3.2-3b qwen-2.5-3b \
        --models-dir models \
        --sample 25 \
        --out analysis_reports/04_llm_bench.md

Prerequisites
-------------
* `pip install llama-cpp-python` (CPU build is fine for this hardware)
* Each named model's GGUF in `--models-dir`. Filenames + HF repo URLs
  come from `aegis.detection.llm_triage._MODEL_REGISTRY`. The harness
  prints a copy-pasteable `huggingface-cli download` command for each
  missing model and exits non-zero rather than silently skipping.

Output
------
Markdown report sorted by "useful narrative rate" — the fraction of
sample events where the model produced a valid JSON triage object
with a non-trivial summary. That's the metric that should drive the
ship-default decision per the audit's open question #2.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.detection.llm_triage import (
    LlamaCppBackend,
    StaticBackend,
    TriageResult,
    build_prompt,
    parse_triage_output,
    model_info,
    _MODEL_REGISTRY,
)


def sample_events(db_path: Path, *,
                  limit: int = 25,
                  min_severity: str = "high") -> list[Event]:
    """Pull `limit` recent high-severity events that have a `case_id`
    in their data — those are the ones an operator would actually want
    triage on. Falls back to plain high-severity if no case-tagged
    events exist."""
    bus = EventBus(db_path=str(db_path))
    rows = bus.query_events(severity=min_severity, limit=limit * 4)
    out: list[Event] = []
    for r in rows:
        try:
            data = (json.loads(r["data"])
                    if isinstance(r.get("data"), str) else (r.get("data") or {}))
        except (TypeError, json.JSONDecodeError):
            data = {}
        case = (data.get("case") or {}) if isinstance(data, dict) else {}
        case_id = data.get("case_id") if isinstance(data, dict) else None
        if not (case.get("case_id") or case_id):
            continue
        out.append(Event(
            category=EventCategory(r["category"]) if r.get("category") else EventCategory.RESPONSE_ALERT,
            severity=Severity(r["severity"]) if r.get("severity") else Severity.HIGH,
            source=r.get("source") or "",
            data=data if isinstance(data, dict) else {},
            timestamp=float(r.get("timestamp") or 0.0),
            mitre_attack=r.get("mitre_attack") or "",
        ))
        if len(out) >= limit:
            break
    if not out:
        # Fall back: high-severity even without case_id, just to give
        # the bench *something* to chew on. Lower-fidelity but better
        # than zero samples on a fresh install.
        for r in rows[:limit]:
            try:
                data = (json.loads(r["data"])
                        if isinstance(r.get("data"), str) else (r.get("data") or {}))
            except (TypeError, json.JSONDecodeError):
                data = {}
            out.append(Event(
                category=EventCategory(r["category"]) if r.get("category") else EventCategory.RESPONSE_ALERT,
                severity=Severity(r["severity"]) if r.get("severity") else Severity.HIGH,
                source=r.get("source") or "",
                data=data if isinstance(data, dict) else {},
                timestamp=float(r.get("timestamp") or 0.0),
                mitre_attack=r.get("mitre_attack") or "",
            ))
    return out


def synthetic_events(n: int = 25) -> list[Event]:
    """Fallback corpus when events.db has no useful samples — the
    cases AEGIS shipped with (honeytoken trip, YARA hit on dropper,
    persistence drift, etc.)."""
    templates = [
        {"category": EventCategory.DETECTION_HONEYTOKEN, "severity": Severity.HIGH,
         "source": "honey", "mitre": "T1083",
         "data": {"action": "canary_modified", "rule_name": "Honeytoken tripped",
                  "rule_id": "HONEY-CANARY_MODIFIED",
                  "path": r"C:\Users\alice\Documents\wallet.dat",
                  "template": "wallet", "case_id": "synth-honey-1"}},
        {"category": EventCategory.DETECTION_YARA, "severity": Severity.HIGH,
         "source": "yara", "mitre": "T1059",
         "data": {"rule_name": "suspicious_powershell_script",
                  "rule_id": "suspicious_powershell_script",
                  "filepath": r"C:\Windows\Temp\update.ps1",
                  "case_id": "synth-yara-1", "pid": 4242,
                  "cmdline": "powershell -nop -w hidden -enc QQBC..."}},
        {"category": EventCategory.DETECTION_ANOMALY, "severity": Severity.MEDIUM,
         "source": "anomaly", "mitre": "T1057",
         "data": {"rule_name": "Isolation Forest outlier",
                  "score": -0.41, "pid": 1234,
                  "name": "node.exe", "cmdline": "node /c/dev/server.js",
                  "case_id": "synth-anom-1"}},
        {"category": EventCategory.RESPONSE_PERSISTENCE, "severity": Severity.HIGH,
         "source": "response", "mitre": "T1547.001",
         "data": {"rule_name": "Persistence indicator",
                  "persistence_category": "reg::Run",
                  "persistence_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\evil",
                  "case_id": "synth-persist-1"}},
        {"category": EventCategory.DETECTION_SUPPLY_CHAIN, "severity": Severity.MEDIUM,
         "source": "supply_chain", "mitre": "T1195.002",
         "data": {"rule_name": "Typosquat on pip install",
                  "package": "rqeusts", "ecosystem": "pypi",
                  "nearest_legit": "requests",
                  "case_id": "synth-supply-1"}},
    ]
    out: list[Event] = []
    for i in range(n):
        t = templates[i % len(templates)]
        d = dict(t["data"])
        d["case_id"] = f"{d.get('case_id','case')}-{i}"
        out.append(Event(
            category=t["category"], severity=t["severity"],
            source=t["source"], data=d,
            timestamp=time.time() - i,
            mitre_attack=t.get("mitre", ""),
        ))
    return out


def run_one_model(model_name: str, models_dir: Path,
                  events: list[Event],
                  *, n_ctx: int = 4096, max_tokens: int = 256) -> dict:
    info = model_info(model_name)
    if info is None:
        return {"model": model_name, "error": f"unknown model"}
    gguf = models_dir / info["gguf_filename"]
    if not gguf.exists():
        return {
            "model": model_name,
            "error": f"GGUF missing at {gguf}. "
                     f"Download: https://huggingface.co/{info['hf_repo']}",
        }
    try:
        backend = LlamaCppBackend(
            gguf_path=str(gguf), model_label=model_name,
            n_ctx=n_ctx,
        )
    except Exception as e:
        return {"model": model_name, "error": f"backend init: {e}"}

    latencies: list[int] = []
    tokens_out: list[int] = []
    parsed: list[TriageResult] = []
    raw_failures: list[str] = []

    for ev in events:
        sys_p, user_p = build_prompt(ev)
        try:
            out = backend.generate(sys_p, user_p, max_tokens=max_tokens)
        except Exception as e:
            raw_failures.append(f"backend.generate: {e}")
            continue
        latencies.append(int(out.get("latency_ms") or 0))
        tokens_out.append(int(out.get("tokens_out") or 0))
        result = parse_triage_output(out.get("text") or "")
        if result is None:
            raw_failures.append((out.get("text") or "")[:300])
            continue
        parsed.append(result)

    confidence_dist: dict[str, int] = {}
    for r in parsed:
        confidence_dist[r.confidence] = confidence_dist.get(r.confidence, 0) + 1

    n = len(events)
    return {
        "model": model_name,
        "samples": n,
        "parsed": len(parsed),
        "parse_rate": (len(parsed) / n) if n else 0.0,
        "useful_rate": (
            sum(1 for r in parsed if len(r.summary) >= 30) / n if n else 0.0
        ),
        "latency_ms_median": int(statistics.median(latencies)) if latencies else 0,
        "latency_ms_p95": int(statistics.quantiles(latencies, n=20)[-1])
                          if len(latencies) >= 20 else
                          (max(latencies) if latencies else 0),
        "tokens_out_median": int(statistics.median(tokens_out)) if tokens_out else 0,
        "confidence_dist": confidence_dist,
        "raw_failures_first3": raw_failures[:3],
    }


def render_report(rows: list[dict], events: list[Event],
                  *, db_path: Path, sample_source: str) -> str:
    lines: list[str] = [
        "# AEGIS — LLM Triage Benchmark",
        "",
        f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Sample source: {sample_source}",
        f"- DB path: {db_path}",
        f"- Sample size: {len(events)} events",
        "",
        "## Results",
        "",
        "| Model | Parsed | Parse rate | Useful rate | Latency p50 | Latency p95 | Tok-out p50 | Confidence dist |",
        "|---|---|---|---|---|---|---|---|",
    ]
    rows_sorted = sorted(rows,
                         key=lambda r: r.get("useful_rate", 0), reverse=True)
    for r in rows_sorted:
        if "error" in r:
            lines.append(f"| {r['model']} | — | — | — | — | — | — | "
                         f"ERROR: {r['error']} |")
            continue
        cd = r["confidence_dist"]
        cd_str = ", ".join(f"{k}:{v}" for k, v in sorted(cd.items())) or "—"
        lines.append(
            f"| {r['model']} | {r['parsed']}/{r['samples']} | "
            f"{r['parse_rate']:.0%} | {r['useful_rate']:.0%} | "
            f"{r['latency_ms_median']} ms | {r['latency_ms_p95']} ms | "
            f"{r['tokens_out_median']} | {cd_str} |"
        )
    lines += ["", "## Recommendation",
              "",
              "Pick the model with the highest **useful rate** that fits "
              "the target host's RAM. Use latency-p95 to set the "
              "max_tokens_out cap so the worst case stays under the "
              "operator's tolerance budget.", ""]

    failure_rows = [r for r in rows
                    if r.get("raw_failures_first3")]
    if failure_rows:
        lines += ["## Sample parse failures",
                  "",
                  "First three unparseable outputs per model — useful for "
                  "tightening the system prompt or adjusting `max_tokens_out`.",
                  ""]
        for r in failure_rows:
            lines += [f"### {r['model']}", "", "```"]
            for f in r["raw_failures_first3"]:
                lines += [f, "---"]
            lines += ["```", ""]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", required=True,
                        choices=sorted(_MODEL_REGISTRY))
    parser.add_argument("--models-dir", default="models")
    parser.add_argument("--db", default="data/events.db",
                        help="Path to AEGIS events.db (sample source)")
    parser.add_argument("--sample", type=int, default=25)
    parser.add_argument("--n-ctx", type=int, default=4096)
    parser.add_argument("--max-tokens", type=int, default=256)
    parser.add_argument("--out", default="analysis_reports/04_llm_bench.md")
    parser.add_argument("--synthetic", action="store_true",
                        help="Use the built-in synthetic corpus instead of "
                             "events.db. Useful on a fresh install.")
    args = parser.parse_args(argv)

    models_dir = Path(args.models_dir)

    db_path = Path(args.db)
    if args.synthetic or not db_path.exists():
        events = synthetic_events(n=args.sample)
        sample_source = "synthetic" if args.synthetic else f"synthetic (no {db_path})"
    else:
        events = sample_events(db_path, limit=args.sample)
        if not events:
            events = synthetic_events(n=args.sample)
            sample_source = f"synthetic (no case-tagged events in {db_path})"
        else:
            sample_source = f"events.db (case-tagged high-severity)"

    print(f"Sample: {len(events)} events from {sample_source}")
    print(f"Models: {args.models}")
    print()

    rows: list[dict] = []
    for name in args.models:
        print(f"--- {name} ---")
        t0 = time.time()
        row = run_one_model(name, models_dir, events,
                            n_ctx=args.n_ctx, max_tokens=args.max_tokens)
        elapsed = time.time() - t0
        if "error" in row:
            print(f"  ERROR: {row['error']}")
        else:
            print(f"  parsed {row['parsed']}/{row['samples']}, "
                  f"useful {row['useful_rate']:.0%}, "
                  f"p50 {row['latency_ms_median']}ms, "
                  f"p95 {row['latency_ms_p95']}ms "
                  f"({elapsed:.1f}s wall)")
        rows.append(row)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        render_report(rows, events, db_path=db_path, sample_source=sample_source),
        encoding="utf-8",
    )
    print(f"\nReport written: {out_path}")
    return 0 if all("error" not in r for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
