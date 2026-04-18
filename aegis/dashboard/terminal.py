"""
AEGIS Terminal Dashboard
=========================
Live terminal UI showing:
  - System health status
  - Recent alerts (color-coded by severity)
  - Active monitors status
  - Process activity
  - Detection statistics

Built with Rich for cross-platform terminal rendering.
"""

import time
import threading
import logging
from collections import deque
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.live import Live
from rich import box

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.dashboard")

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class Dashboard:
    """Rich-based terminal dashboard for AEGIS."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self.console = Console()
        self._running = False
        self._thread = None
        self._refresh_interval = config.get("refresh_interval_ms", 1000) / 1000.0

        # Event buffers
        self._alerts: deque[Event] = deque(maxlen=config.get("max_alerts_displayed", 30))
        self._detections: deque[Event] = deque(maxlen=20)
        self._file_events: deque[Event] = deque(maxlen=15)
        self._process_events: deque[Event] = deque(maxlen=15)
        self._network_events: deque[Event] = deque(maxlen=10)

        # Stats
        self._stats = {
            "events_total": 0,
            "detections": 0,
            "alerts": 0,
            "kills": 0,
            "quarantines": 0,
        }
        self._start_time = time.time()

        # Monitor status
        self._monitor_status = {}

    def start(self):
        """Subscribe to events and start the dashboard."""
        self.bus.subscribe("*", self._on_event)
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="aegis-dashboard")
        self._thread.start()
        logger.info("Dashboard started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _on_event(self, event: Event):
        """Collect events for display."""
        self._stats["events_total"] += 1

        cat = event.category.value

        if cat.startswith("detection."):
            self._detections.append(event)
            self._stats["detections"] += 1

        if cat.startswith("response.alert"):
            self._alerts.append(event)
            self._stats["alerts"] += 1

        if cat == "response.kill":
            self._stats["kills"] += 1
            self._alerts.append(event)

        if cat == "response.quarantine":
            self._stats["quarantines"] += 1
            self._alerts.append(event)

        if cat.startswith("file."):
            self._file_events.append(event)

        if cat.startswith("proc."):
            self._process_events.append(event)

        if cat.startswith("net."):
            self._network_events.append(event)

        if cat == "system.start":
            self._monitor_status[event.source] = "ACTIVE"

        if cat == "system.health":
            monitors = event.data.get("monitors", {})
            for name, status in monitors.items():
                self._monitor_status[name] = "ACTIVE" if status else "DOWN"

    def _run(self):
        """Main dashboard render loop."""
        try:
            with Live(self._render(), console=self.console,
                       refresh_per_second=1, screen=True) as live:
                while self._running:
                    live.update(self._render())
                    time.sleep(self._refresh_interval)
        except Exception as e:
            logger.error(f"Dashboard error: {e}")

    def _render(self) -> Layout:
        """Build the full dashboard layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=3),
        )

        layout["left"].split_column(
            Layout(name="status", size=12),
            Layout(name="stats", size=10),
            Layout(name="monitors"),
        )

        layout["right"].split_column(
            Layout(name="alerts"),
            Layout(name="activity", size=14),
        )

        layout["header"].update(self._render_header())
        layout["status"].update(self._render_status())
        layout["stats"].update(self._render_stats())
        layout["monitors"].update(self._render_monitors())
        layout["alerts"].update(self._render_alerts())
        layout["activity"].update(self._render_activity())
        layout["footer"].update(self._render_footer())

        return layout

    def _render_header(self) -> Panel:
        header = Text()
        header.append("  AEGIS ", style="bold green")
        header.append("Adaptive Endpoint Guardian Intelligence System", style="dim")
        header.append("  │  ", style="dim")
        header.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="cyan")
        return Panel(header, style="green", box=box.HEAVY)

    def _render_status(self) -> Panel:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(width=20)
        table.add_column()

        uptime = int(time.time() - self._start_time)
        h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60

        det = self._stats["detections"]
        status_style = "green" if det == 0 else ("yellow" if det < 5 else "red")
        status_text = "ALL CLEAR" if det == 0 else f"{det} DETECTION(S)"

        table.add_row("Status:", Text(status_text, style=f"bold {status_style}"))
        table.add_row("Uptime:", Text(f"{h:02d}:{m:02d}:{s:02d}", style="cyan"))
        table.add_row("Events:", Text(str(self._stats["events_total"]), style="white"))
        table.add_row("Detections:", Text(str(det), style=status_style))

        return Panel(table, title="[bold]System Status[/bold]", border_style="green",
                     box=box.ROUNDED)

    def _render_stats(self) -> Panel:
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(width=16)
        table.add_column()

        table.add_row("Alerts:", Text(str(self._stats["alerts"]), style="yellow"))
        table.add_row("Kills:", Text(str(self._stats["kills"]), style="red"))
        table.add_row("Quarantined:", Text(str(self._stats["quarantines"]), style="red"))
        table.add_row("File events:", Text(str(len(self._file_events)), style="dim"))
        table.add_row("Proc events:", Text(str(len(self._process_events)), style="dim"))
        table.add_row("Net events:", Text(str(len(self._network_events)), style="dim"))

        return Panel(table, title="[bold]Response Stats[/bold]", border_style="blue",
                     box=box.ROUNDED)

    def _render_monitors(self) -> Panel:
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
        table.add_column("Monitor", style="bold")
        table.add_column("Status", justify="center")

        monitors = {
            "FIM": "fim",
            "Process": "procmon",
            "Network": "netmon",
            "Resource": "resmon",
            "YARA": "yara",
            "Behavioral": "behavioral",
            "Response": "response",
        }

        for display, key in monitors.items():
            status = self._monitor_status.get(key, "STARTING")
            if status == "ACTIVE":
                style = "green"
                icon = "● "
            elif status == "DOWN":
                style = "red"
                icon = "○ "
            else:
                style = "yellow"
                icon = "◌ "
            table.add_row(display, Text(f"{icon}{status}", style=style))

        return Panel(table, title="[bold]Monitors[/bold]", border_style="cyan",
                     box=box.ROUNDED)

    def _render_alerts(self) -> Panel:
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1),
                      expand=True)
        table.add_column("Time", width=8, style="dim")
        table.add_column("Sev", width=4, justify="center")
        table.add_column("Source", width=10)
        table.add_column("Details", ratio=1)

        alerts = list(self._alerts)[-20:]
        # Combine detections too
        for event in list(self._detections)[-10:]:
            if event not in alerts:
                alerts.append(event)

        alerts.sort(key=lambda e: e.timestamp, reverse=True)

        for event in alerts[:20]:
            ts = datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S")
            sev_color = SEVERITY_COLORS.get(event.severity, "dim")
            icon = SEVERITY_ICONS.get(event.severity, "?")
            sev = Text(icon, style=sev_color)

            # Build detail string
            data = event.data
            detail_parts = []
            if rule := data.get("rule_name", data.get("rule", "")):
                detail_parts.append(rule)
            if rule_id := data.get("rule_id", ""):
                detail_parts.append(f"[{rule_id}]")
            if pid := data.get("pid", data.get("source_event", {}).get("pid", "")):
                detail_parts.append(f"PID:{pid}")
            if filepath := data.get("filepath", data.get("path", data.get("original_path", ""))):
                detail_parts.append(filepath[-40:])
            if action := data.get("action", ""):
                detail_parts.append(action)
            if summary := data.get("summary", ""):
                detail_parts.append(summary[-50:])

            detail = " │ ".join(detail_parts) if detail_parts else event.category.value

            table.add_row(ts, sev, Text(event.source, style="cyan"), detail[:80])

        title = "[bold]Alerts & Detections[/bold]"
        if self._stats["detections"] > 0:
            title = f"[bold red]⚠ Alerts & Detections ({self._stats['detections']})[/bold red]"

        return Panel(table, title=title, border_style="red" if self._stats["detections"] > 0 else "yellow",
                     box=box.ROUNDED)

    def _render_activity(self) -> Panel:
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1), expand=True)
        table.add_column("Time", width=8, style="dim")
        table.add_column("Type", width=12)
        table.add_column("Details", ratio=1)

        # Mix recent file and process events
        recent = []
        for e in list(self._file_events)[-5:]:
            recent.append(("FILE", e))
        for e in list(self._process_events)[-5:]:
            recent.append(("PROC", e))
        for e in list(self._network_events)[-3:]:
            recent.append(("NET", e))

        recent.sort(key=lambda x: x[1].timestamp, reverse=True)

        for etype, event in recent[:10]:
            ts = datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S")

            if etype == "FILE":
                action = event.data.get("action", "?")
                path = event.data.get("path", "?")
                detail = f"{action}: {path[-50:]}"
                type_style = "green"
            elif etype == "PROC":
                name = event.data.get("name", "?")
                pid = event.data.get("pid", "?")
                detail = f"{name} (PID:{pid})"
                type_style = "blue"
            else:
                remote = event.data.get("remote_addr", "?")
                port = event.data.get("remote_port", "?")
                proc = event.data.get("process", "?")
                detail = f"{proc} → {remote}:{port}"
                type_style = "cyan"

            table.add_row(ts, Text(etype, style=type_style), detail[:60])

        return Panel(table, title="[bold]Recent Activity[/bold]", border_style="dim",
                     box=box.ROUNDED)

    def _render_footer(self) -> Panel:
        footer = Text()
        footer.append(" Ctrl+C to stop ", style="bold dim")
        footer.append("│", style="dim")
        footer.append(f" Events/sec: ~{self._events_per_sec():.1f} ", style="dim")
        footer.append("│", style="dim")
        footer.append(" AEGIS v0.1.0 ", style="dim green")
        return Panel(footer, style="dim", box=box.HEAVY)

    def _events_per_sec(self) -> float:
        elapsed = max(time.time() - self._start_time, 1)
        return self._stats["events_total"] / elapsed
