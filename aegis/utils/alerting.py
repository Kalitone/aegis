"""
AEGIS Alerting
================
JSON structured logging, rotation, and outbound alert transports.

Components:
  * JsonFormatter       — logging.Formatter that emits one JSON object per line.
  * setup_logging()     — wires stdout, a rotating file handler, and an
                          optional JSON file handler.
  * WebhookAlerter      — subscribes to response.alert and forwards CRITICAL /
                          HIGH detections to Slack, Discord, Teams, or a
                          generic JSON endpoint.
  * EmailAlerter        — SMTP alerter for the same event stream.

Network calls run in a daemon thread with a small queue so that a slow or
failing webhook can never stall the event bus.
"""

import os
import sys
import ssl
import json
import time
import queue
import smtplib
import logging
import logging.handlers
import threading
import urllib.request
from email.mime.text import MIMEText
from pathlib import Path

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.utils.ocsf import event_to_ocsf

logger = logging.getLogger("aegis.utils.alerting")


# ── Structured logging ────────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    """One JSON object per log record. SIEM-friendly."""

    DEFAULT_FIELDS = (
        "levelname", "name", "message", "created", "pathname", "lineno",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": record.created,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Allow extra=... to pass arbitrary fields
        for key, value in record.__dict__.items():
            if key.startswith("aegis_"):
                payload[key[6:]] = value
        return json.dumps(payload, default=str)


def setup_logging(config) -> None:
    """
    Configure logging from an AegisConfig-like object.
    Adds a rotating text log, optional JSON log, and stdout handler.
    """
    level_name = config.get("core.log_level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    text_log = Path(config.get("core.log_file", "logs/aegis.log"))
    json_log_path = config.get("core.log_json_file", "")
    max_bytes = int(config.get("core.log_max_bytes", 10 * 1024 * 1024))
    backups = int(config.get("core.log_backup_count", 14))

    text_log.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    # Remove any pre-existing handlers (important for re-init in tests)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    root.addHandler(stream)

    rotating = logging.handlers.RotatingFileHandler(
        text_log, maxBytes=max_bytes, backupCount=backups,
        encoding="utf-8",
    )
    rotating.setFormatter(fmt)
    root.addHandler(rotating)

    if json_log_path:
        Path(json_log_path).parent.mkdir(parents=True, exist_ok=True)
        json_handler = logging.handlers.RotatingFileHandler(
            json_log_path, maxBytes=max_bytes, backupCount=backups,
            encoding="utf-8",
        )
        json_handler.setFormatter(JsonFormatter())
        root.addHandler(json_handler)


# ── Alert transports ──────────────────────────────────────────────

class _AsyncTransport:
    """Base: background thread consumes a queue, never blocks publishers."""

    def __init__(self, name: str):
        self._q: queue.Queue = queue.Queue(maxsize=500)
        self._running = False
        self._thread = None
        self._name = name

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._worker, daemon=True, name=f"aegis-{self._name}"
        )
        self._thread.start()

    def stop(self):
        self._running = False
        try:
            self._q.put_nowait(None)
        except queue.Full:
            pass

    def submit(self, event: Event):
        try:
            self._q.put_nowait(event)
        except queue.Full:
            logger.warning(f"{self._name} queue full — dropping event")

    def _worker(self):
        while self._running:
            try:
                event = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            if event is None:
                return
            try:
                self._deliver(event)
            except Exception as e:
                logger.error(f"{self._name} delivery failed: {e}")

    def _deliver(self, event: Event):
        raise NotImplementedError


class WebhookAlerter(_AsyncTransport):
    """
    Ships alerts to Slack/Discord/Teams/generic JSON webhook endpoints.
    For Slack/Discord, a simple `text` payload is used.
    Generic endpoints receive the full event dict.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        super().__init__("webhook")
        self.bus = event_bus
        self.url = config.get("url", "") or os.environ.get("AEGIS_WEBHOOK_URL", "")
        self.style = config.get("style", "generic")     # slack|discord|teams|generic
        self.min_severity = config.get("min_severity", "high")
        self.timeout = float(config.get("timeout_seconds", 5))

    def start(self):
        if not self.url:
            logger.info("WebhookAlerter: no URL configured, disabled")
            return
        super().start()
        self.bus.subscribe(EventCategory.RESPONSE_ALERT.value, self._on_alert)
        self.bus.subscribe("detection.*", self._on_alert)
        logger.info(f"WebhookAlerter started ({self.style} → {self._redact_url()})")

    def _redact_url(self) -> str:
        # Never log the full URL — it may contain a secret token.
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            return f"{parsed.scheme}://{parsed.hostname}/…"
        except Exception:
            return self.url[:15] + "…"

    def _on_alert(self, event: Event):
        if not self._passes_severity(event):
            return
        self.submit(event)

    def _passes_severity(self, event: Event) -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                 Severity.HIGH, Severity.CRITICAL]
        try:
            min_idx = [s.value for s in order].index(self.min_severity)
            cur_idx = [s.value for s in order].index(event.severity.value)
        except ValueError:
            return True
        return cur_idx >= min_idx

    def _build_payload(self, event: Event) -> dict:
        summary = self._summary(event)
        if self.style == "slack":
            return {"text": summary}
        if self.style == "discord":
            return {"content": summary}
        if self.style == "teams":
            return {"@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": "AEGIS alert",
                    "text": summary}
        return event.to_dict()

    def _summary(self, event: Event) -> str:
        d = event.data
        return (f":rotating_light: *AEGIS* [{event.severity.value.upper()}] "
                f"{d.get('rule_name', d.get('rule', event.category.value))}\n"
                f"Source: {event.source} | Host: {event.hostname or 'local'} | "
                f"ATT&CK: {event.mitre_attack or 'n/a'}\n"
                f"Details: {json.dumps({k: v for k, v in d.items() if k != 'source_event'})[:1200]}")

    def _deliver(self, event: Event):
        payload = self._build_payload(event)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"webhook returned {resp.status}")


class ToastAlerter(_AsyncTransport):
    """
    Native Windows 10/11 toast notifications for alerts.
    Uses `winotify` (pure-Python, no compilation). On non-Windows platforms or
    when winotify isn't installed, the alerter logs a warning and stays disabled
    rather than failing — same soft-dependency pattern as the anomaly detector.
    """

    SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

    def __init__(self, event_bus: EventBus, config: dict):
        super().__init__("toast")
        self.bus = event_bus
        self.enabled = bool(config.get("enabled", True))
        self.min_severity = config.get("min_severity", "high")
        self.app_id = config.get("app_id", "AEGIS")
        self.icon_path = config.get("icon_path", "")
        self._winotify = None

    def start(self):
        if not self.enabled:
            logger.info("ToastAlerter: disabled in config")
            return
        if sys.platform != "win32":
            logger.info("ToastAlerter: non-Windows platform, disabled")
            return
        try:
            import winotify  # type: ignore
            self._winotify = winotify
        except ImportError:
            logger.info("ToastAlerter: winotify not installed (pip install winotify), disabled")
            return
        super().start()
        self.bus.subscribe(EventCategory.RESPONSE_ALERT.value, self._on_alert)
        self.bus.subscribe("detection.*", self._on_alert)
        logger.info(f"ToastAlerter started (min_severity={self.min_severity})")

    def _on_alert(self, event: Event):
        try:
            if (self.SEVERITY_ORDER.index(event.severity.value)
                    < self.SEVERITY_ORDER.index(self.min_severity)):
                return
        except ValueError:
            pass
        self.submit(event)

    def _deliver(self, event: Event):
        d = event.data
        title = f"AEGIS [{event.severity.value.upper()}] {d.get('rule_name', d.get('rule', event.category.value))}"
        body_bits = [f"src={event.source}"]
        if event.mitre_attack:
            body_bits.append(f"ATT&CK={event.mitre_attack}")
        for k in ("pid", "name", "cmdline", "path", "file"):
            if k in d:
                v = str(d[k])
                body_bits.append(f"{k}={v[:120]}")
                break
        body = " | ".join(body_bits)
        toast = self._winotify.Notification(
            app_id=self.app_id,
            title=title[:64],
            msg=body[:200],
            icon=self.icon_path or "",
        )
        # Critical alerts ring the loud sound; others use default.
        if event.severity.value == "critical":
            toast.set_audio(self._winotify.audio.LoopingAlarm, loop=False)
        toast.show()


class OcsfFileSink:
    """Writes every AEGIS event in OCSF v1.1.0 JSON-lines to a
    rotating file, suitable for SIEM ingestion (Splunk Forwarder /
    Filebeat / Vector / fluentd tailing the file).

    Subscribes to the wildcard `*` so the file is the full audit
    stream — not just alerts — which is what makes the hash-chained
    log a credible export artifact. Per-event mapping is delegated to
    `aegis.utils.ocsf.event_to_ocsf`; this class is just transport.

    Synchronous on the publisher thread on purpose: rotating-file
    writes are fast (≪1 ms) and putting OCSF behind a queue would
    create a window where a crash could lose post-publish events
    that are already in the hash chain. If the path is on a slow
    disk and you need async behaviour, point it at a tmpfs / a
    ramdisk that an external forwarder drains.
    """

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.enabled = bool(config.get("enabled", False))
        self.path = Path(config.get("path", "logs/ocsf.json"))
        self.max_bytes = int(config.get("max_bytes", 10 * 1024 * 1024))
        self.backups = int(config.get("backup_count", 7))
        self.product_name = config.get("product_name", "AEGIS")
        self.product_vendor = config.get("product_vendor", "AEGIS")
        self.product_version = config.get("product_version", "0.2.0")
        self.schema_version = config.get("schema_version", "1.1.0")
        self._handler: logging.handlers.RotatingFileHandler | None = None
        self._logger: logging.Logger | None = None
        self._running = False

    def start(self):
        if not self.enabled:
            logger.info("OcsfFileSink: disabled in config")
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(f"OcsfFileSink: cannot create {self.path.parent}: {e}")
            return

        # Dedicated logger so we don't pollute root with passthrough
        # JSON-lines. propagate=False prevents the OCSF stream from
        # appearing in the regular text log.
        self._logger = logging.getLogger("aegis.ocsf.sink")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        for h in list(self._logger.handlers):
            self._logger.removeHandler(h)

        self._handler = logging.handlers.RotatingFileHandler(
            self.path, maxBytes=self.max_bytes, backupCount=self.backups,
            encoding="utf-8",
        )
        # Passthrough formatter — the message we log IS the JSON line.
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(self._handler)

        self.bus.subscribe("*", self._on_event)
        self._running = True
        logger.info(f"OcsfFileSink started → {self.path}")

    def stop(self):
        self._running = False
        if self._handler is not None:
            try:
                self._handler.close()
            except Exception:
                pass
        if self._logger is not None and self._handler is not None:
            try:
                self._logger.removeHandler(self._handler)
            except Exception:
                pass
        self._handler = None
        self._logger = None

    def _on_event(self, event: Event):
        if not self._running or self._logger is None:
            return
        try:
            obj = event_to_ocsf(
                event,
                product_name=self.product_name,
                product_vendor=self.product_vendor,
                product_version=self.product_version,
                schema_version=self.schema_version,
            )
            self._logger.info(json.dumps(obj, default=str))
        except Exception as e:
            # OCSF errors are NEVER allowed to break the hot path —
            # the bus has already accepted the event and persisted to
            # the chain; an export glitch can't undo that.
            logger.error(f"OcsfFileSink: emit failed: {e}", exc_info=False)


class EmailAlerter(_AsyncTransport):
    """Simple SMTP alerter. TLS used when port 587/465."""

    def __init__(self, event_bus: EventBus, config: dict):
        super().__init__("email")
        self.bus = event_bus
        self.host = config.get("smtp_host", "")
        self.port = int(config.get("smtp_port", 587))
        self.username = config.get("smtp_username", "")
        self.password = config.get("smtp_password", "") or os.environ.get("AEGIS_SMTP_PASSWORD", "")
        self.from_addr = config.get("from_address", "aegis@localhost")
        self.to_addrs = config.get("to_addresses", [])
        if isinstance(self.to_addrs, str):
            self.to_addrs = [self.to_addrs]
        self.min_severity = config.get("min_severity", "critical")

    def start(self):
        if not (self.host and self.to_addrs):
            logger.info("EmailAlerter: not fully configured, disabled")
            return
        super().start()
        self.bus.subscribe(EventCategory.RESPONSE_ALERT.value, self._on_alert)
        self.bus.subscribe("detection.*", self._on_alert)
        logger.info(f"EmailAlerter started → {self.to_addrs}")

    def _on_alert(self, event: Event):
        if not self._passes_severity(event):
            return
        self.submit(event)

    def _passes_severity(self, event: Event) -> bool:
        order = ["info", "low", "medium", "high", "critical"]
        try:
            return order.index(event.severity.value) >= order.index(self.min_severity)
        except ValueError:
            return True

    def _deliver(self, event: Event):
        body = json.dumps(event.to_dict(), indent=2, default=str)
        msg = MIMEText(body)
        msg["Subject"] = (f"[AEGIS {event.severity.value.upper()}] "
                          f"{event.data.get('rule_name', event.category.value)}")
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        if self.port == 465:
            server = smtplib.SMTP_SSL(self.host, self.port, timeout=10)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=10)
            server.ehlo()
            if self.port == 587:
                # TLS: create_default_context() verifies server certificate chain.
                # Hostname verification happens during the TLS handshake.
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
        try:
            if self.username:
                server.login(self.username, self.password)
            server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                pass
