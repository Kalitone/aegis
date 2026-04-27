"""
AEGIS — Local LLM Alert Triage
==============================
Subscribes to `response.alert` events, builds a redacted prompt
from the case context, runs it through a small local LLM, and
publishes a `detection.llm_summary` event with:

  * `confidence`  — likely-fp | suspicious | very-likely-malicious
  * `summary`     — one-paragraph operator narrative
  * `next_steps`  — up to three suggested actions (free-form strings)
  * `model_used`  — string label (e.g. `phi-3.5-mini-q4`)
  * `latency_ms`  — wall-clock inference latency
  * `tokens_in`/`tokens_out` — for budget tracking

Design contract
---------------
* **Output is advisory.** The LLM's confidence label MUST NOT feed
  back into auto-quarantine / auto-kill decisions — the prompt
  injection threat is real (an attacker who can place a string in
  a path or cmdline could try to talk the model into "this is a
  benign Windows update"). Output augments the dashboard inspector
  pane only.
* **Redacted prompts.** No env vars, no file contents, no full
  cmdlines beyond the first 256 chars. Paths, rule IDs, MITRE
  techniques, and the case execution chain only. The LLM should
  never see secrets that aren't already in the public event log.
* **Pluggable backend.** `LlmBackend` is a Protocol; the default
  `LlamaCppBackend` lazy-imports `llama_cpp` so AEGIS still starts
  on hosts where the dep isn't installed (the feature degrades
  to disabled-with-log-line).
* **Soft-fail.** Backend errors never propagate into the bus —
  they log at WARNING and the case still proceeds without the
  enrichment.

Why a small model
-----------------
The audit envelope is "narrative under 500 ms on a CPU-only host
with ~6 GB free RAM." That sets the size at 3-4B params Q4_K_M
(~2.5 GB on disk, ~3.5 GB at runtime). Phi-3.5-mini-instruct is
the ship-default; the YAML knob `detection.llm_triage.model`
lets operators with more headroom move up to 7-8B (Qwen-2.5-7B,
Llama-3.1-8B) or 14B (Phi-4) for stronger reasoning.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.detection.llm_triage")


# ── Model registry ──────────────────────────────────────────────────
# Maps friendly model names to the GGUF filename + a canonical
# Hugging Face URL so the loader can hand operators an exact
# download command. We deliberately don't auto-download — making
# the user opt in to a 2-10 GB download is the right friction.

_MODEL_REGISTRY: dict[str, dict] = {
    # Ship default after the 2026-04-26 benchmark on a Ryzen 7 5825U
    # (CPU-only, 8.9 GB free RAM): Qwen beat Phi-3.5-mini on speed
    # (p50 8.4s vs 12.8s, p95 10.0s vs 30.3s) at the same 100% parse
    # rate, with an Apache-2.0 license (cleaner for redistribution).
    # See analysis_reports/04_llm_bench.md for the full table.
    "qwen-2.5-3b": {
        "gguf_filename": "Qwen2.5-3B-Instruct-Q4_K_M.gguf",
        "hf_repo": "bartowski/Qwen2.5-3B-Instruct-GGUF",
        "approx_disk_gb": 2.0,
        "approx_runtime_ram_gb": 3.0,
        "params_b": 3.1,
        "default": True,
    },
    "phi-3.5-mini": {
        "gguf_filename": "Phi-3.5-mini-instruct-Q4_K_M.gguf",
        "hf_repo": "bartowski/Phi-3.5-mini-instruct-GGUF",
        "approx_disk_gb": 2.4,
        "approx_runtime_ram_gb": 3.5,
        "params_b": 3.8,
    },
    "llama-3.2-3b": {
        "gguf_filename": "Llama-3.2-3B-Instruct-Q4_K_M.gguf",
        "hf_repo": "bartowski/Llama-3.2-3B-Instruct-GGUF",
        "approx_disk_gb": 2.0,
        "approx_runtime_ram_gb": 3.0,
        "params_b": 3.2,
    },
    "qwen-2.5-7b": {
        "gguf_filename": "Qwen2.5-7B-Instruct-Q4_K_M.gguf",
        "hf_repo": "bartowski/Qwen2.5-7B-Instruct-GGUF",
        "approx_disk_gb": 4.5,
        "approx_runtime_ram_gb": 5.5,
        "params_b": 7.6,
    },
    "phi-4": {
        "gguf_filename": "phi-4-Q4_K_M.gguf",
        "hf_repo": "bartowski/phi-4-GGUF",
        "approx_disk_gb": 8.4,
        "approx_runtime_ram_gb": 10.0,
        "params_b": 14.7,
    },
}


def model_info(name: str) -> Optional[dict]:
    return _MODEL_REGISTRY.get(name)


def default_model() -> str:
    for name, info in _MODEL_REGISTRY.items():
        if info.get("default"):
            return name
    return next(iter(_MODEL_REGISTRY))


# ── Triage result type ─────────────────────────────────────────────

_VALID_CONFIDENCE = ("likely-fp", "suspicious", "very-likely-malicious")


@dataclass
class TriageResult:
    confidence: str
    summary: str
    next_steps: list[str] = field(default_factory=list)
    model_used: str = ""
    latency_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    raw_output: str = ""

    def to_dict(self) -> dict:
        return {
            "confidence": self.confidence,
            "summary": self.summary,
            "next_steps": list(self.next_steps),
            "model_used": self.model_used,
            "latency_ms": self.latency_ms,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
        }


# ── Prompt builder (redaction-aware) ────────────────────────────────

_SYSTEM_PROMPT = (
    "You are AEGIS-TRIAGE, a security analyst assistant integrated into "
    "an open-source EDR. For each detection event you receive, output "
    "EXACTLY ONE valid JSON object on ONE line, with these keys:\n"
    '  "confidence":  one of "likely-fp" | "suspicious" | "very-likely-malicious"\n'
    '  "summary":     one to two sentences in plain English, no markdown\n'
    '  "next_steps":  array of 1-3 short imperative strings\n'
    "Do NOT include keys other than these three. Do NOT preface with "
    "'Here is the JSON' or any text outside the object.\n"
    "\n"
    "CALIBRATION GUIDE — pick the label that matches the evidence:\n"
    "  - likely-fp: the event reads as normal user / system activity. "
    "Examples: anomaly score on a known-good process during a routine "
    "workload spike; YARA hit on a string that's in scope for both "
    "malware AND legitimate tooling but the surrounding context is "
    "clearly benign.\n"
    "  - suspicious: ambiguous — the pattern fits both legitimate and "
    "malicious activity and the redacted event alone cannot disambiguate. "
    "This is the DEFAULT label when in doubt; do not escalate without "
    "corroborating signals.\n"
    "  - very-likely-malicious: reserve for events whose detection "
    "mechanism has near-zero false-positive rate by construction "
    "(honeytoken trips, known-bad SHA256 matches, multiple-stage "
    "indicators in a single event). Most events are NOT this.\n"
    "\n"
    "EXAMPLE 1 — clear false positive:\n"
    'Input: {"category":"detection.anomaly","severity":"medium",'
    '"source":"anomaly","rule_name":"Isolation Forest outlier",'
    '"process":{"name":"chrome.exe","cmdline":"--type=renderer"}}\n'
    'Output: {"confidence":"likely-fp",'
    '"summary":"Chrome renderer process with normal flags. Anomaly '
    'score reflects natural variance in browser workload.",'
    '"next_steps":["Acknowledge"]}\n'
    "\n"
    "EXAMPLE 2 — genuine ambiguity (most common):\n"
    'Input: {"category":"detection.yara","severity":"high",'
    '"source":"yara","rule_id":"suspicious_powershell_script",'
    '"file":{"path":"C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Temp\\\\update.ps1"},'
    '"process":{"cmdline":"powershell.exe -nop -w hidden -EncodedCommand QQ..."}}\n'
    'Output: {"confidence":"suspicious",'
    '"summary":"PowerShell with -EncodedCommand from user temp directory '
    'is both a common admin tooling pattern and a malware staging '
    'pattern. Decoded command needed to disambiguate.",'
    '"next_steps":["Decode the EncodedCommand argument",'
    '"Walk parent process tree","Check for recent admin activity"]}\n'
    "\n"
    "EXAMPLE 3 — strong signal:\n"
    'Input: {"category":"detection.honeytoken","severity":"high",'
    '"source":"honey","rule_id":"HONEY-CANARY_MODIFIED",'
    '"file":{"path":"C:\\\\Users\\\\u\\\\Documents\\\\wallet.dat"}}\n'
    'Output: {"confidence":"very-likely-malicious",'
    '"summary":"Honeytoken canary modified — these decoys have '
    'near-zero false-positive rate. Only a process walking user '
    'documents would touch them, strongly indicating ransomware '
    'encryption walk or credential theft.",'
    '"next_steps":["Identify modifying process via FIM event",'
    '"Quarantine parent","Forensic snapshot"]}\n'
)


def build_prompt(event: Event, *, system_prompt: str = _SYSTEM_PROMPT) -> tuple[str, str]:
    """Return (system_prompt, user_prompt). The user prompt is the
    redacted event projection — no env vars, no file contents, no
    full cmdlines beyond the first 256 chars."""
    d = event.data or {}
    case = d.get("case") or {}
    original = d.get("original_event") or {}
    o_data = original.get("data") if isinstance(original, dict) else {}
    o_data = o_data or {}

    redacted = {
        "category": (event.category.value
                     if hasattr(event.category, "value")
                     else str(event.category)),
        "severity": (event.severity.value
                     if hasattr(event.severity, "value")
                     else str(event.severity)),
        "source": event.source,
        "mitre_attack": event.mitre_attack or o_data.get("mitre_attack") or "",
        "rule_id": d.get("rule_id") or o_data.get("rule_id") or "",
        "rule_name": d.get("rule_name") or o_data.get("rule_name") or "",
        "process": {
            "pid": d.get("pid") or o_data.get("pid"),
            "name": (d.get("name") or o_data.get("name") or "")[:120],
            "cmdline": (d.get("cmdline") or o_data.get("cmdline") or "")[:256],
        },
        "file": {
            "path": (d.get("path") or d.get("filepath")
                     or o_data.get("filepath") or o_data.get("path") or "")[:512],
            "sha256": d.get("sha256") or o_data.get("sha256") or "",
        },
        "case_id": case.get("case_id") or d.get("case_id") or "",
    }
    user_prompt = (
        "AEGIS detection event (redacted):\n"
        + json.dumps(redacted, default=str, sort_keys=True)
        + "\n\nProduce the JSON triage object."
    )
    return system_prompt, user_prompt


# ── Output parsing ──────────────────────────────────────────────────

_JSON_OBJ_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)


def parse_triage_output(raw: str) -> Optional[TriageResult]:
    """Pull the first JSON object out of `raw` and coerce to
    TriageResult. Resilient to small models that prepend a
    'Here is...' line, wrap in markdown fencing, or — as observed
    with Llama-3.2-3B — emit the JSON fields without the outer
    `{...}` wrapper."""
    if not raw:
        return None
    candidates: list[str] = []
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        candidates.append(fence.group(1))
    candidates.extend(_JSON_OBJ_RE.findall(raw))

    # Brace-elision fallback: if the raw output looks like a JSON
    # object body (`"key": value, ...`) but is missing the outer
    # braces, try wrapping it. Targets Llama-3.2-3B's failure mode.
    stripped = raw.strip().strip("`").strip()
    if stripped and not stripped.startswith("{") and '"confidence"' in stripped:
        # Trim a trailing comma if the model emitted one before EOL
        wrapped = "{" + stripped.rstrip().rstrip(",") + "}"
        candidates.append(wrapped)

    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        confidence = str(obj.get("confidence", "")).strip().lower()
        if confidence not in _VALID_CONFIDENCE:
            continue
        summary = str(obj.get("summary", "")).strip()
        next_steps = obj.get("next_steps") or []
        if not isinstance(next_steps, list):
            next_steps = [str(next_steps)]
        next_steps = [str(s).strip() for s in next_steps if str(s).strip()][:3]
        return TriageResult(
            confidence=confidence,
            summary=summary,
            next_steps=next_steps,
            raw_output=raw,
        )
    return None


# ── Backend protocol + implementations ─────────────────────────────

class LlmBackend(Protocol):
    """Minimal contract — anything that can turn a (system, user)
    prompt pair into a string response. Used by the engine and by
    the benchmark harness."""

    name: str

    def generate(self, system_prompt: str, user_prompt: str,
                 *, max_tokens: int = 256) -> dict: ...


class LlamaCppBackend:
    """Real backend backed by `llama_cpp.Llama`. Lazy-imports the
    package so AEGIS doesn't hard-fail when it's missing — the
    triage feature simply doesn't start."""

    def __init__(self, *,
                 gguf_path: str,
                 model_label: str,
                 n_ctx: int = 4096,
                 n_threads: Optional[int] = None,
                 seed: int = 0):
        try:
            from llama_cpp import Llama  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "llama-cpp-python is not installed. "
                "Install with: pip install llama-cpp-python"
            ) from e
        if not Path(gguf_path).exists():
            raise FileNotFoundError(f"GGUF model not found at {gguf_path}")
        self.name = model_label
        self._llm = Llama(
            model_path=str(gguf_path),
            n_ctx=int(n_ctx),
            n_threads=n_threads,
            seed=seed,
            verbose=False,
        )

    def generate(self, system_prompt: str, user_prompt: str,
                 *, max_tokens: int = 256) -> dict:
        # `create_chat_completion` is the broadly-supported entry
        # point; small models follow chat templates better than the
        # raw completion API.
        t0 = time.time()
        resp = self._llm.create_chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=int(max_tokens),
            temperature=0.0,
        )
        latency_ms = int((time.time() - t0) * 1000)
        choice = (resp.get("choices") or [{}])[0]
        text = (choice.get("message") or {}).get("content") or ""
        usage = resp.get("usage") or {}
        return {
            "text": text,
            "latency_ms": latency_ms,
            "tokens_in": int(usage.get("prompt_tokens") or 0),
            "tokens_out": int(usage.get("completion_tokens") or 0),
        }


class StaticBackend:
    """Deterministic stub used by tests and as a fallback when no
    real model is configured. Returns a fixed JSON response keyed
    off the rule severity so unit tests can assert against it."""

    name = "static-stub"

    def __init__(self, response_text: Optional[str] = None):
        self._response = response_text or json.dumps({
            "confidence": "suspicious",
            "summary": "Static-stub triage output. Replace with a real "
                       "backend before relying on confidence labels.",
            "next_steps": ["Replace with a real LLM backend"],
        })

    def generate(self, system_prompt: str, user_prompt: str,
                 *, max_tokens: int = 256) -> dict:
        return {
            "text": self._response,
            "latency_ms": 0,
            "tokens_in": len(system_prompt) + len(user_prompt),
            "tokens_out": len(self._response),
        }


# ── Engine ─────────────────────────────────────────────────────────

class LlmTriage:
    """Background subscriber to `response.alert`. One worker thread
    pulls from a bounded queue so the bus is never blocked by a slow
    inference."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", False))
        self.model_name = str(self.config.get("model") or default_model())
        self.models_dir = Path(self.config.get("models_dir", "models"))
        self.n_ctx = int(self.config.get("n_ctx", 4096))
        self.n_threads = self.config.get("n_threads")
        self.max_tokens_out = int(self.config.get("max_tokens_out", 256))
        self.queue_size = int(self.config.get("queue_size", 64))
        self._backend: Optional[LlmBackend] = self.config.get("backend")
        self._q: queue.Queue = queue.Queue(maxsize=self.queue_size)
        self._running = False
        self._thread: Optional[threading.Thread] = None

    # -- public ------------------------------------------------------
    def start(self):
        if not self.enabled:
            logger.info("LlmTriage: disabled in config")
            return
        if self._backend is None:
            try:
                self._backend = self._build_default_backend()
            except Exception as e:
                logger.warning(f"LlmTriage: backend unavailable, disabling: {e}")
                self.enabled = False
                return
        self._running = True
        self._thread = threading.Thread(
            target=self._worker, daemon=True, name="aegis-llm-triage",
        )
        self._thread.start()
        self.bus.subscribe("response.alert", self._on_alert)
        logger.info(
            f"LlmTriage started (model={self._backend.name}, n_ctx={self.n_ctx})"
        )

    def stop(self):
        self._running = False
        try:
            self._q.put_nowait(None)
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=2)

    def triage_event(self, event: Event) -> Optional[TriageResult]:
        """Synchronous one-shot — used by the benchmark harness +
        tests. Production traffic goes through the queue."""
        if self._backend is None:
            self._backend = self._build_default_backend()
        return self._run_once(event)

    # -- internals --------------------------------------------------
    def _build_default_backend(self) -> LlmBackend:
        info = model_info(self.model_name)
        if info is None:
            raise RuntimeError(f"Unknown model '{self.model_name}'. "
                               f"Known: {sorted(_MODEL_REGISTRY)}")
        gguf = self.models_dir / info["gguf_filename"]
        if not gguf.exists():
            raise FileNotFoundError(
                f"GGUF not found at {gguf}. Download from "
                f"https://huggingface.co/{info['hf_repo']} into {self.models_dir}/"
            )
        return LlamaCppBackend(
            gguf_path=str(gguf),
            model_label=self.model_name,
            n_ctx=self.n_ctx,
            n_threads=self.n_threads,
        )

    def _on_alert(self, event: Event):
        try:
            self._q.put_nowait(event)
        except queue.Full:
            logger.debug("LlmTriage queue full — skipping triage")

    def _worker(self):
        while self._running:
            try:
                event = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            if event is None:
                return
            try:
                self._run_once(event)
            except Exception as e:
                logger.warning(f"LlmTriage inference failed: {e}")

    def _run_once(self, event: Event) -> Optional[TriageResult]:
        if self._backend is None:
            return None
        sys_p, user_p = build_prompt(event)
        out = self._backend.generate(sys_p, user_p, max_tokens=self.max_tokens_out)
        result = parse_triage_output(out.get("text") or "")
        if result is None:
            logger.debug("LlmTriage: backend returned unparseable output")
            return None
        result.model_used = self._backend.name
        result.latency_ms = int(out.get("latency_ms") or 0)
        result.tokens_in = int(out.get("tokens_in") or 0)
        result.tokens_out = int(out.get("tokens_out") or 0)

        # Publish the enrichment back onto the bus. The dashboard
        # inspector pane keys on `case_id` to attach this narrative
        # to the original event.
        case = (event.data or {}).get("case") or {}
        case_id = case.get("case_id") or (event.data or {}).get("case_id")
        sev_for_event = (
            Severity.HIGH if result.confidence == "very-likely-malicious"
            else Severity.MEDIUM if result.confidence == "suspicious"
            else Severity.LOW
        )
        self.bus.publish(Event(
            category=EventCategory.DETECTION_BEHAVIORAL,
            severity=sev_for_event,
            source="llm_triage",
            data={
                "rule_name": "LLM triage narrative",
                "rule_id": "LLM-TRIAGE",
                "case_id": case_id,
                "triage": result.to_dict(),
                "advisory": True,        # NEVER feeds destructive actions
            },
        ))
        return result


__all__ = [
    "LlmTriage",
    "LlmBackend",
    "LlamaCppBackend",
    "StaticBackend",
    "TriageResult",
    "build_prompt",
    "parse_triage_output",
    "model_info",
    "default_model",
    "_MODEL_REGISTRY",
]
