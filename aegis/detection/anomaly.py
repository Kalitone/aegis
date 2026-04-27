"""
AEGIS Anomaly Detection
=========================
Isolation Forest over per-process feature vectors. Two modes:

  Training:   collect feature vectors for a baseline period, fit Isolation
              Forest, persist to disk.
  Detection:  on every proc.create event, extract features, score with the
              trained model; publish detection.anomaly when the score
              exceeds the anomaly threshold.

Feature vector (fixed order so saved models remain portable):
    [cpu_percent, memory_mb, num_fds, child_count, net_connections,
     file_writes_per_sec, cmdline_entropy]

The model is small (a few hundred KB) and fast (sub-millisecond inference
per vector). scikit-learn + joblib are soft dependencies — if unavailable
the detector disables itself cleanly rather than breaking AEGIS startup.
"""

import os
import time
import math
import logging
import threading
from collections import deque
from pathlib import Path
from typing import Optional

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.monitors.process_mon import cmdline_entropy


_SEVERITY_BY_NAME: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class _StormBreaker:
    """Rolling-window rate limiter for anomaly detections.

    Audit found 326 anomaly detections in 6.5 days — most were
    duplicate score-tail noise rather than distinct incidents. The
    breaker keeps a deque of recent admit-times; once more than
    `threshold` events occur inside `window_s`, it trips and silences
    further detections for `cool_off_s`. The deque drains naturally
    so the breaker re-arms without external clean-up.
    """

    def __init__(self, *, threshold: int, window_s: float, cool_off_s: float):
        self.threshold = max(1, int(threshold))
        self.window_s = float(window_s)
        self.cool_off_s = float(cool_off_s)
        self._times: deque[float] = deque()
        self._tripped_until: float = 0.0
        self.trips: int = 0
        self.suppressed: int = 0

    def try_admit(self, now: float) -> bool:
        """True to publish, False to suppress."""
        if now < self._tripped_until:
            self.suppressed += 1
            return False
        cutoff = now - self.window_s
        while self._times and self._times[0] < cutoff:
            self._times.popleft()
        self._times.append(now)
        if len(self._times) > self.threshold:
            self._tripped_until = now + self.cool_off_s
            self.trips += 1
            self.suppressed += 1
            return False
        return True

    def stats(self) -> dict:
        return {
            "threshold": self.threshold,
            "window_s": self.window_s,
            "cool_off_s": self.cool_off_s,
            "trips": self.trips,
            "suppressed": self.suppressed,
            "tripped": time.time() < self._tripped_until,
        }

logger = logging.getLogger("aegis.detection.anomaly")

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    np = None
    IsolationForest = None
    joblib = None
    SKLEARN_AVAILABLE = False


FEATURE_NAMES = [
    "cpu_percent",
    "memory_mb",
    "num_fds",
    "child_count",
    "net_connections",
    "file_writes_per_sec",
    "cmdline_entropy",
]


def extract_features(event_data: dict) -> list[float]:
    """Extract the fixed-order feature vector from a proc.create event payload."""
    cmdline = event_data.get("cmdline", "")
    return [
        float(event_data.get("cpu_percent", 0) or 0),
        float(event_data.get("memory_mb", 0) or 0),
        float(event_data.get("num_fds", 0) or 0),
        float(len(event_data.get("children_pids", []) or [])),
        float(event_data.get("net_connections", 0) or 0),
        float(event_data.get("file_writes_per_sec", 0) or 0),
        float(event_data.get("cmdline_entropy", cmdline_entropy(cmdline) if cmdline else 0)),
    ]


class AnomalyDetector:
    """
    Subscribes to proc.create events. In training mode, buffers feature
    vectors. On `train()` it fits an IsolationForest and persists it.
    In detection mode, it loads the model and scores each new event.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self.model_path = Path(config.get("model_path", "data/anomaly_model.pkl"))
        self.checkpoint_path = Path(
            config.get("checkpoint_path",
                       str(self.model_path.with_suffix(".training.pkl")))
        )
        self.checkpoint_every = int(config.get("checkpoint_every", 50))
        self.contamination = float(config.get("contamination", 0.01))
        self.training_period_hours = float(config.get("training_period_hours", 24))
        self.min_training_samples = int(config.get("min_training_samples", 200))
        self.auto_train = bool(config.get("auto_train", True))

        # Default severity for an Isolation Forest hit. Audit found that
        # promoting these to HIGH (the old behaviour for score < -0.2)
        # mixed score-tail noise into the same channel as YARA matches —
        # operators couldn't tell signal from drift. Default MEDIUM keeps
        # them visible without triggering the high-severity action chain.
        sev_name = str(config.get("severity", "medium")).lower()
        self._base_severity = _SEVERITY_BY_NAME.get(sev_name, Severity.MEDIUM)

        # Storm breaker: cap how many detections we publish per window.
        # Disabled by default (None) only if the operator explicitly
        # turns it off; the audit pretty clearly says we want this on.
        breaker_cfg = config.get("storm_breaker", {}) or {}
        if bool(breaker_cfg.get("enabled", True)):
            self._storm_breaker = _StormBreaker(
                threshold=int(breaker_cfg.get("threshold", 5)),
                window_s=float(breaker_cfg.get("window_s", 300)),
                cool_off_s=float(breaker_cfg.get("cool_off_s", 300)),
            )
        else:
            self._storm_breaker = None

        self._lock = threading.Lock()
        self._training_buffer: list[list[float]] = []
        self._training_start_time: float = 0.0
        self._samples_since_checkpoint = 0
        self._model = None
        self._mode = "idle"              # "training" | "detecting" | "idle"
        self._running = False
        self._eval_count = 0
        self._detection_count = 0
        self._last_detection_ts = 0.0
        # debounce: don't flood on identical workload
        self._dedup_window = 5.0
        self._recent_hashes: dict[int, float] = {}

    def start(self):
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn not installed — anomaly detector disabled")
            return

        # Load existing model if present, otherwise enter training mode.
        if self.model_path.exists():
            try:
                self._model = joblib.load(self.model_path)
                self._mode = "detecting"
                logger.info(f"Anomaly model loaded: {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load anomaly model: {e}. Retraining.")
                self._model = None

        if self._model is None and self.auto_train:
            self._mode = "training"
            resumed = self._load_checkpoint()
            if not resumed:
                self._training_start_time = time.time()
                logger.info(f"Anomaly detector in TRAINING mode for "
                            f"{self.training_period_hours}h")
            else:
                elapsed_h = (time.time() - self._training_start_time) / 3600
                remaining_h = max(0.0, self.training_period_hours - elapsed_h)
                logger.info(
                    f"Anomaly detector RESUMED training: "
                    f"{len(self._training_buffer)} samples, "
                    f"{elapsed_h:.1f}h elapsed, {remaining_h:.1f}h remaining"
                )

        self.bus.subscribe(EventCategory.PROC_CREATE.value, self._on_event)
        self.bus.subscribe(EventCategory.PROC_SUSPICIOUS.value, self._on_event)
        self._running = True

    def _on_event(self, event: Event):
        try:
            features = extract_features(event.data)
        except Exception as e:
            logger.debug(f"Could not extract features: {e}")
            return

        if self._mode == "training":
            self._record_training_sample(features)
        elif self._mode == "detecting" and self._model is not None:
            self._score_and_publish(features, event)

    def _record_training_sample(self, features: list[float]):
        do_checkpoint = False
        do_train = False
        with self._lock:
            self._training_buffer.append(features)
            self._samples_since_checkpoint += 1
            if self._samples_since_checkpoint >= self.checkpoint_every:
                do_checkpoint = True
                self._samples_since_checkpoint = 0
            elapsed = time.time() - self._training_start_time
            period_s = self.training_period_hours * 3600
            # Finish training either when time elapses or we have enough samples
            # for tests / quick bootstrap.
            if elapsed >= period_s and len(self._training_buffer) >= self.min_training_samples:
                do_train = True
        if do_checkpoint:
            self._save_checkpoint()
        if do_train:
            self.train()

    def train(self) -> bool:
        """Fit IsolationForest on buffered samples. Returns True if succeeded."""
        if not SKLEARN_AVAILABLE:
            return False
        with self._lock:
            samples = list(self._training_buffer)
        if len(samples) < self.min_training_samples:
            logger.warning(
                f"Not enough samples to train anomaly model "
                f"({len(samples)} < {self.min_training_samples})"
            )
            return False

        X = np.array(samples)
        model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        model.fit(X)

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, self.model_path)
        self._model = model
        self._mode = "detecting"
        # Training complete — drop the checkpoint so a future retrain starts fresh.
        try:
            if self.checkpoint_path.exists():
                self.checkpoint_path.unlink()
        except Exception:
            pass
        logger.info(f"Anomaly model trained on {len(samples)} samples "
                    f"and saved to {self.model_path}")
        return True

    def _save_checkpoint(self):
        """Persist training buffer + start time so a restart can resume."""
        if not SKLEARN_AVAILABLE:
            return
        with self._lock:
            payload = {
                "version": 1,
                "training_start_time": self._training_start_time,
                "samples": list(self._training_buffer),
                "feature_names": FEATURE_NAMES,
            }
        try:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.checkpoint_path.with_suffix(".tmp")
            joblib.dump(payload, tmp)
            os.replace(tmp, self.checkpoint_path)
        except Exception as e:
            logger.warning(f"Anomaly checkpoint save failed: {e}")

    def _load_checkpoint(self) -> bool:
        """Restore buffer + start_time from disk. Returns True if resumed."""
        if not self.checkpoint_path.exists():
            return False
        try:
            payload = joblib.load(self.checkpoint_path)
        except Exception as e:
            logger.warning(f"Anomaly checkpoint corrupt, ignoring: {e}")
            return False
        if payload.get("feature_names") != FEATURE_NAMES:
            logger.warning("Anomaly checkpoint has stale feature schema, discarding")
            try:
                self.checkpoint_path.unlink()
            except Exception:
                pass
            return False
        self._training_buffer = list(payload.get("samples", []))
        self._training_start_time = float(
            payload.get("training_start_time") or time.time()
        )
        return True

    def force_train(self, samples: list[list[float]]) -> bool:
        """Train from an external sample set (used by tests and CLI)."""
        with self._lock:
            self._training_buffer = list(samples)
            self._training_start_time = 0
        return self.train()

    def _score_and_publish(self, features: list[float], event: Event):
        self._eval_count += 1
        try:
            X = np.array([features])
            # score_samples: higher == more normal; predict: -1 anomaly, 1 normal
            score = float(self._model.score_samples(X)[0])
            pred = int(self._model.predict(X)[0])
        except Exception as e:
            logger.error(f"Anomaly inference failed: {e}")
            return

        if pred != -1:
            return

        # Deduplicate near-identical feature vectors within the debounce window.
        sig = hash(tuple(round(f, 2) for f in features))
        now = time.time()
        last = self._recent_hashes.get(sig, 0)
        if now - last < self._dedup_window:
            return
        self._recent_hashes[sig] = now
        # Trim old hashes occasionally
        if len(self._recent_hashes) > 1000:
            self._recent_hashes = {
                k: v for k, v in self._recent_hashes.items()
                if now - v < 60
            }

        if self._storm_breaker is not None and not self._storm_breaker.try_admit(now):
            logger.debug(
                f"ANOMALY suppressed by storm breaker: "
                f"score={score:.3f} pid={event.data.get('pid')}"
            )
            return

        self._detection_count += 1
        self._last_detection_ts = now

        self.bus.publish(Event(
            category=EventCategory.DETECTION_ANOMALY,
            severity=self._base_severity,
            source="anomaly",
            data={
                "score": score,
                "features": dict(zip(FEATURE_NAMES, features)),
                "pid": event.data.get("pid"),
                "process": event.data.get("name", ""),
                "cmdline": event.data.get("cmdline", "")[:300],
                "rule_name": "Isolation Forest outlier",
                "model_path": str(self.model_path),
            },
        ))
        logger.warning(
            f"ANOMALY: score={score:.3f} pid={event.data.get('pid')} "
            f"cmd='{event.data.get('cmdline','')[:80]}'"
        )

    def stop(self):
        self._running = False
        # If we already have enough samples and the training window has elapsed,
        # finalize the model now. Otherwise checkpoint so the next start resumes.
        if self._mode == "training":
            elapsed = time.time() - self._training_start_time
            period_s = self.training_period_hours * 3600
            if (elapsed >= period_s
                    and len(self._training_buffer) >= self.min_training_samples):
                self.train()
            elif self._training_buffer:
                self._save_checkpoint()

    @property
    def stats(self) -> dict:
        return {
            "mode": self._mode,
            "model_loaded": self._model is not None,
            "training_samples": len(self._training_buffer),
            "evaluations": self._eval_count,
            "detections": self._detection_count,
            "running": self._running,
        }

    @property
    def is_running(self) -> bool:
        return self._running
