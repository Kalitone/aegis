"""
AEGIS Main Entry Point
========================
Orchestrates all modules: monitors, detection engines, response, and dashboard.
Handles startup, shutdown, and signal handling.

Usage:
    python -m aegis                          # Default config
    python -m aegis --config path/to/yaml    # Custom config
    python -m aegis --scan /path/to/dir      # One-shot YARA scan
    python -m aegis --harden [--apply]       # Run hardening audit (optionally applying fixes)
    python -m aegis --update-rules           # Pull community YARA rules
    python -m aegis --scan-pkg NAME [--ecosystem pypi|npm]
    python -m aegis --scan-pkg-path DIR
"""

import sys
import signal
import logging
import argparse
import time
import platform
import socket
import threading

from aegis.core import EventBus, Event, EventCategory, Severity
from aegis.core.config import AegisConfig
from aegis.monitors.fim import FileIntegrityMonitor
from aegis.monitors.process_mon import ProcessMonitor
from aegis.monitors.network_mon import NetworkMonitor
from aegis.monitors.resource_mon import ResourceMonitor
from aegis.monitors.persistence import PersistenceMonitor
from aegis.monitors.dns_mon import DnsMonitor
from aegis.detection.yara_scanner import YaraScanner
from aegis.detection.behavioral import BehavioralEngine, RULES as BEHAVIORAL_RULES
from aegis.detection.anomaly import AnomalyDetector
from aegis.detection.supply_chain import SupplyChainScanner
from aegis.detection.sigma_loader import load_sigma_rules
from aegis.detection.threat_intel import ThreatIntel
from aegis.response import ResponseEngine
from aegis.utils.alerting import setup_logging, WebhookAlerter, EmailAlerter, ToastAlerter
from aegis.utils.self_protect import (
    verify_manifest, parent_is_service_host, spawn_watchdog, mark_clean_shutdown,
    build_manifest,
)
from aegis.dashboard.web import WebDashboard


BANNER = r"""
    ___    ________________
   /   |  / ____/ ____/  _/ _____
  / /| | / __/ / / __ / / / ___/
 / ___ |/ /___/ /_/ // /  (__  )
/_/  |_/_____/\____/___/ /____/

 Adaptive Endpoint Guardian Intelligence System
 v0.2.0 — Defense in Depth
"""


class Aegis:
    """Main AEGIS orchestrator."""

    def __init__(self, config_path: str | None = None):
        self.config_path = config_path
        self.config = AegisConfig(config_path)
        setup_logging(self.config)
        self.logger = logging.getLogger("aegis.main")

        # ── Tamper resistance gate (run BEFORE we touch any state) ──
        sp_cfg = self.config.get("self_protect", {}) or {}
        if sp_cfg.get("manifest_check", True):
            ok, problems = verify_manifest(".", config_path or "config/aegis.yaml")
            if not ok:
                self.logger.error("INTEGRITY CHECK FAILED:\n  - "
                                  + "\n  - ".join(problems))
                if sp_cfg.get("strict", False):
                    raise SystemExit(2)
                else:
                    self.logger.warning("Continuing despite integrity drift "
                                        "(self_protect.strict=false)")
        if sp_cfg.get("parent_check", False):
            if not parent_is_service_host():
                self.logger.error("Parent process check failed — refusing to start")
                raise SystemExit(3)

        # Core
        db_path = self.config.get("core.event_db", "data/events.db")
        self.event_bus = EventBus(db_path=db_path)

        # Monitors
        self.fim = FileIntegrityMonitor(self.event_bus, self.config.get("monitors.fim", {}))
        self.procmon = ProcessMonitor(self.event_bus, self.config.get("monitors.process", {}))
        self.netmon = NetworkMonitor(self.event_bus, self.config.get("monitors.network", {}))
        self.resmon = ResourceMonitor(self.event_bus, self.config.get("monitors.resource", {}))
        self.persistence = PersistenceMonitor(self.event_bus, self.config.get("monitors.persistence", {}))
        self.dns = DnsMonitor(self.event_bus, self.config.get("monitors.dns", {}))

        # Detection
        self.yara = YaraScanner(self.event_bus, self.config.get("detection.yara", {}))
        self.behavioral = BehavioralEngine(self.event_bus, self.config.get("detection.behavioral", {}))
        # Optionally augment with Sigma rules.
        sigma_cfg = self.config.get("detection.sigma", {}) or {}
        if sigma_cfg.get("enabled", False):
            sigma_rules = load_sigma_rules(
                sigma_cfg.get("rules_dir", "rules/sigma"),
                max_rules=sigma_cfg.get("max_rules", 0) or None,
            )
            if sigma_rules:
                self.behavioral.rules.extend(sigma_rules)
                # Recompile pattern cache for the new rules.
                import re as _re
                for r in sigma_rules:
                    self.behavioral._compiled[r.rule_id] = [
                        _re.compile(p, _re.IGNORECASE) for p in r.cmdline_patterns
                    ]
                self.logger.info(f"Sigma: merged {len(sigma_rules)} rules")
        self.anomaly = AnomalyDetector(self.event_bus, self.config.get("detection.anomaly", {}))
        self.supply_chain = SupplyChainScanner(
            self.event_bus, self.config.get("detection.supply_chain", {})
        )
        self.threat_intel = ThreatIntel(self.event_bus, self.config.get("detection.threat_intel", {}))

        # Response
        self.response = ResponseEngine(self.event_bus, self.config.get("response", {}))

        # Alerting
        self.webhook = WebhookAlerter(self.event_bus, self.config.get("alerting.webhook", {}))
        self.email = EmailAlerter(self.event_bus, self.config.get("alerting.email", {}))
        self.toast = ToastAlerter(self.event_bus, self.config.get("alerting.toast", {}))

        # Web dashboard
        full_cfg = {"core": self.config.get("core", {}),
                    "dashboard_web": self.config.get("dashboard_web", {})}
        self.web = WebDashboard(self.event_bus, full_cfg, aegis_ref=self)

        self._running = False
        self._rule_update_thread: threading.Thread | None = None

    def start(self):
        print(BANNER)
        self.logger.info("=" * 60)
        self.logger.info("AEGIS Starting")
        self.logger.info(f"Platform: {platform.system()} {platform.release()}")
        self.logger.info(f"Hostname: {socket.gethostname()}")
        self.logger.info(f"Python: {platform.python_version()}")
        self.logger.info("=" * 60)

        self.event_bus.publish(Event(
            category=EventCategory.SYSTEM_START,
            severity=Severity.INFO,
            source="main",
            hostname=socket.gethostname(),
            data={
                "platform": platform.system(),
                "hostname": socket.gethostname(),
                "version": "0.2.0",
            },
        ))

        # Alerting first so it catches every downstream event
        self.webhook.start()
        self.email.start()
        self.toast.start()

        self.response.start()
        self.logger.info("✓ Response engine started")

        # Bring the web dashboard up early so it's reachable while the
        # FIM baseline (which can take minutes on C:\Windows) is building.
        try:
            self.web.start()
            self.logger.info("✓ Web dashboard started")
        except Exception as e:
            self.logger.warning(f"Web dashboard failed to start: {e}")

        self.yara.start()
        self.logger.info("✓ YARA scanner started")
        self.behavioral.start()
        self.logger.info("✓ Behavioral engine started")

        if self.config.get("detection.anomaly.enabled", True):
            self.anomaly.start()
            self.logger.info(f"✓ Anomaly detector started (mode={self.anomaly.stats.get('mode')})")

        if self.config.get("detection.supply_chain.enabled", True):
            self.supply_chain.start()
            self.logger.info("✓ Supply chain scanner started")

        if self.config.get("monitors.process.enabled", True):
            self.procmon.start()
            self.logger.info("✓ Process monitor started")
        if self.config.get("monitors.network.enabled", True):
            self.netmon.start()
            self.logger.info("✓ Network monitor started")
        if self.config.get("monitors.resource.enabled", True):
            self.resmon.start()
            self.logger.info("✓ Resource monitor started")
        if self.config.get("monitors.fim.enabled", True):
            self.fim.start()
            self.logger.info("✓ File integrity monitor started")

        if self.config.get("monitors.persistence.enabled", True):
            self.persistence.start()
            self.logger.info("✓ Persistence monitor started")
        if self.config.get("monitors.dns.enabled", True):
            self.dns.start()
            self.logger.info("✓ DNS monitor started")
        if self.config.get("detection.threat_intel.enabled", True):
            self.threat_intel.start()
            self.logger.info("✓ Threat intel feeds started")

        # Periodic in-memory YARA scan (defaults to every 10 min). On Linux
        # it needs root; on Windows it needs SYSTEM (which the NSSM service is).
        mem_cfg = self.config.get("detection.yara.memory_scan", {}) or {}
        if mem_cfg.get("enabled", False):
            self.yara.start_memory_scan_loop(
                interval_seconds=float(mem_cfg.get("interval_seconds", 600)),
                max_pids=int(mem_cfg.get("max_pids", 0)),
            )
            self.logger.info("✓ YARA memory scan loop started")

        # Daily rule auto-update.
        upd_cfg = self.config.get("rule_updates", {}) or {}
        if upd_cfg.get("enabled", False):
            self._start_rule_update_loop(
                interval_hours=float(upd_cfg.get("interval_hours", 24)),
                rules_dir=self.config.get("detection.yara.rules_dir", "rules/yara"),
            )

        # Watchdog (external supervisor that respawns us if we die).
        if (self.config.get("self_protect.watchdog", False)
                and not self.config.get("self_protect.no_watchdog_env", False)):
            argv = [sys.executable, "-m", "aegis"]
            if self.config_path:
                argv += ["--config", self.config_path]
            spawn_watchdog(argv)

        self._running = True
        self.logger.info("=" * 60)
        self.logger.info("AEGIS fully operational. All systems active.")
        self.logger.info("=" * 60)

    def stop(self):
        self.logger.info("AEGIS shutting down...")
        # Tell the watchdog this is intentional so it doesn't relaunch us.
        mark_clean_shutdown()
        self._running = False

        self.fim.stop()
        self.procmon.stop()
        self.netmon.stop()
        self.resmon.stop()
        self.persistence.stop()
        self.dns.stop()
        self.anomaly.stop()
        self.supply_chain.stop()
        self.threat_intel.stop()
        self.response.stop()
        self.webhook.stop()
        self.email.stop()
        self.toast.stop()
        self.web.stop()
        self.event_bus.shutdown()

        self.logger.info("AEGIS stopped. Stay safe.")

    def _start_rule_update_loop(self, interval_hours: float, rules_dir: str):
        from aegis.utils.rule_updater import update as run_update

        def _loop():
            while self._running:
                slept = 0.0
                while self._running and slept < interval_hours * 3600:
                    time.sleep(5.0)
                    slept += 5.0
                if not self._running:
                    return
                try:
                    self.logger.info("Scheduled rule update starting...")
                    res = run_update(rules_dir)
                    self.logger.info(f"Scheduled rule update done: {res}")
                except Exception as e:
                    self.logger.error(f"Scheduled rule update failed: {e}")

        self._rule_update_thread = threading.Thread(
            target=_loop, daemon=True, name="aegis-ruleupdate"
        )
        self._rule_update_thread.start()
        self.logger.info(f"Rule auto-update scheduled every {interval_hours}h")

    def run_forever(self):
        self.start()

        def signal_handler(sig, frame):
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, "SIGTERM"):
            try:
                signal.signal(signal.SIGTERM, signal_handler)
            except (ValueError, OSError):
                pass  # not main thread or not supported on this OS

        try:
            while self._running:
                time.sleep(1)
                if int(time.time()) % 60 == 0:
                    self._health_check()
        except KeyboardInterrupt:
            self.stop()

    def _health_check(self):
        self.event_bus.publish(Event(
            category=EventCategory.SYSTEM_HEALTH,
            severity=Severity.INFO,
            source="main",
            data={
                "events_processed": self.event_bus.event_count,
                "yara_stats": self.yara.stats,
                "behavioral_stats": self.behavioral.stats,
                "anomaly_stats": self.anomaly.stats,
                "processes_tracked": self.procmon.tracked_count,
                "monitors": {
                    "fim": self.fim.is_running,
                    "procmon": self.procmon.is_running,
                    "netmon": self.netmon.is_running,
                    "resmon": self.resmon.is_running,
                },
            },
        ))


# ── CLI sub-commands ─────────────────────────────────────────────

def _cmd_scan(config: AegisConfig, path: str):
    bus = EventBus()
    scanner = YaraScanner(bus, config.get("detection.yara", {}))
    scanner.start()
    print(f"Scanning {path}...")
    results = scanner.scan_directory(path)
    if results:
        print(f"\n⚠ {len(results)} detection(s):")
        for r in results:
            print(f"  [{r['meta'].get('severity','?')}] {r['rule']} → {r['file']}")
    else:
        print("✓ No threats detected.")


def _cmd_harden(apply_fixes: bool):
    from aegis.hardening import HardeningRunner
    runner = HardeningRunner()
    findings = runner.audit()
    if apply_fixes:
        runner.apply(findings)
    print(runner.report(findings))


def _cmd_update_rules(config: AegisConfig):
    from aegis.utils.rule_updater import update
    rules_dir = config.get("detection.yara.rules_dir", "rules/yara")
    results = update(rules_dir)
    print("\nRule update summary:")
    for name, status in results.items():
        print(f"  {name:20s} {status}")


def _cmd_scan_pkg(config: AegisConfig, name: str, ecosystem: str):
    bus = EventBus()
    scanner = SupplyChainScanner(bus, config.get("detection.supply_chain", {}))
    scanner.start()
    findings = scanner.evaluate_and_publish(name, ecosystem)
    if findings:
        print(f"\n⚠ {len(findings)} supply-chain finding(s) for {name}:")
        for f in findings:
            sev = f["severity"].value if hasattr(f["severity"], "value") else f["severity"]
            print(f"  [{sev}] {f['rule']}: {f['detail']}")
    else:
        print(f"✓ {name} looks clean.")


def _cmd_coverage(as_json: bool):
    from aegis.utils.mitre_coverage import render_text, render_navigator_json
    print(render_navigator_json() if as_json else render_text())


def _cmd_verify_chain(config: AegisConfig):
    db_path = config.get("core.event_db", "data/events.db")
    bus = EventBus(db_path=db_path)
    ok, problems = bus.verify_chain()
    if ok:
        print(f"✓ Event hash chain OK ({bus.event_count} rows checked? — verify ran)")
    else:
        print(f"✗ Event log tampering detected ({len(problems)} issue(s)):")
        for p in problems[:25]:
            print(f"  seq={p['seq']} {p['issue']}")


def _cmd_purge_quarantine(config: AegisConfig, keep_meta: bool = False):
    """Delete every file under the configured quarantine directory."""
    from pathlib import Path
    qdir = Path(config.get("core.quarantine_dir", "quarantine"))
    if not qdir.exists():
        print(f"✓ Quarantine dir {qdir} does not exist, nothing to purge.")
        return
    removed = 0
    failed = 0
    freed = 0
    for entry in qdir.iterdir():
        if not entry.is_file():
            continue
        if keep_meta and entry.name.endswith(".meta.json"):
            continue
        try:
            freed += entry.stat().st_size
            entry.unlink()
            removed += 1
        except Exception:
            failed += 1
    mb = freed / (1024 * 1024)
    print(f"✓ Purged {removed} file(s) from {qdir} ({mb:.1f} MB freed)"
          + (f", {failed} failed" if failed else ""))


def _cmd_reset_chain(config: AegisConfig, yes: bool = False):
    """Archive the event DB and start a fresh hash chain.

    Does NOT touch the anomaly model or training checkpoint, YARA rules,
    quarantine, or any other state — only events.db / .db-wal / .db-shm.
    """
    from pathlib import Path
    import shutil
    db_path = Path(config.get("core.event_db", "data/events.db"))
    targets = [db_path, db_path.with_suffix(db_path.suffix + "-wal"),
               db_path.with_suffix(db_path.suffix + "-shm")]
    existing = [p for p in targets if p.exists()]
    if not existing:
        print(f"✓ No event DB at {db_path} — nothing to reset.")
        return
    # Refuse to clobber a live DB (SQLite WAL open ⇒ service is running).
    wal = db_path.with_suffix(db_path.suffix + "-wal")
    if wal.exists() and wal.stat().st_size > 0:
        print(f"⚠ {wal} is non-empty — the AEGIS service appears to be running.")
        print("  Stop the service first: net stop AEGIS")
        if not yes:
            return
    if not yes:
        total = sum(p.stat().st_size for p in existing)
        print(f"This will archive and clear the event DB at {db_path}")
        print(f"  {len(existing)} file(s), {total/1024:.1f} KB total")
        print("  Anomaly training and quarantine are UNAFFECTED.")
        reply = input("Type RESET to confirm: ").strip()
        if reply != "RESET":
            print("✗ Aborted.")
            return
    stamp = time.strftime("%Y%m%d_%H%M%S")
    archive = db_path.parent / f"events.db.bak-{stamp}"
    archive.mkdir(parents=True, exist_ok=True)
    moved = 0
    for p in existing:
        try:
            shutil.move(str(p), str(archive / p.name))
            moved += 1
        except Exception as e:
            print(f"  failed to move {p}: {e}")
    print(f"✓ Archived {moved} file(s) → {archive}")
    print("✓ Hash chain will restart at seq 1 on next AEGIS start.")


def _cmd_build_manifest(config: AegisConfig):
    from aegis.utils.self_protect import build_manifest as _bm
    cfg_path = config._config_path or "config/aegis.yaml"
    m = _bm(".", cfg_path)
    print(f"✓ Wrote manifest with {m['file_count']} files")


def _cmd_mem_scan(config: AegisConfig):
    bus = EventBus()
    scanner = YaraScanner(bus, config.get("detection.yara", {}))
    scanner.start()
    detections = scanner.scan_processes()
    if detections:
        print(f"⚠ {len(detections)} memory detection(s):")
        for d in detections:
            print(f"  pid={d['pid']:6d}  rule={d['rule']}  process={d['process']}")
    else:
        print("✓ No in-memory YARA matches.")


def _cmd_scan_pkg_path(config: AegisConfig, path: str):
    bus = EventBus()
    scanner = SupplyChainScanner(bus, config.get("detection.supply_chain", {}))
    scanner.start()
    findings = scanner.scan_package_directory(path)
    if findings:
        print(f"\n⚠ {len(findings)} finding(s) in {path}:")
        for f in findings:
            sev = f["severity"].value if hasattr(f["severity"], "value") else f["severity"]
            print(f"  [{sev}] {f['rule']}: {f['detail']}")
    else:
        print(f"✓ {path} looks clean.")


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS — Adaptive Endpoint Guardian Intelligence System",
    )
    parser.add_argument("--config", "-c", default="config/aegis.yaml")
    parser.add_argument("--scan", help="One-shot YARA scan of a directory, then exit")
    parser.add_argument("--harden", action="store_true",
                        help="Run hardening audit")
    parser.add_argument("--apply", action="store_true",
                        help="With --harden, apply fixes (not just report)")
    parser.add_argument("--update-rules", action="store_true",
                        help="Fetch/refresh community YARA rules")
    parser.add_argument("--scan-pkg", help="Scan a pip/npm package name for supply chain risk")
    parser.add_argument("--scan-pkg-path", help="Scan a package directory for supply chain risk")
    parser.add_argument("--ecosystem", choices=["pypi", "npm"], default="pypi",
                        help="Ecosystem for --scan-pkg")
    parser.add_argument("--coverage", action="store_true",
                        help="Print MITRE ATT&CK coverage report and exit")
    parser.add_argument("--coverage-json", action="store_true",
                        help="Emit ATT&CK Navigator-compatible JSON layer")
    parser.add_argument("--verify-chain", action="store_true",
                        help="Verify the event hash chain for tampering")
    parser.add_argument("--build-manifest", action="store_true",
                        help="(Re)build the integrity manifest of config + rules")
    parser.add_argument("--mem-scan", action="store_true",
                        help="One-shot YARA scan of running process memory")
    parser.add_argument("--purge-quarantine", action="store_true",
                        help="Delete every file in the quarantine directory")
    parser.add_argument("--keep-meta", action="store_true",
                        help="With --purge-quarantine, keep .meta.json sidecars")
    parser.add_argument("--reset-chain", action="store_true",
                        help="Archive event DB and restart the hash chain clean "
                             "(anomaly training/quarantine unaffected)")
    parser.add_argument("--yes", action="store_true",
                        help="Skip interactive confirmation (for --reset-chain)")
    args = parser.parse_args()

    config = AegisConfig(args.config)

    if args.scan:
        setup_logging(config)
        _cmd_scan(config, args.scan)
        return
    if args.harden:
        _cmd_harden(args.apply)
        return
    if args.update_rules:
        setup_logging(config)
        _cmd_update_rules(config)
        return
    if args.scan_pkg:
        setup_logging(config)
        _cmd_scan_pkg(config, args.scan_pkg, args.ecosystem)
        return
    if args.scan_pkg_path:
        setup_logging(config)
        _cmd_scan_pkg_path(config, args.scan_pkg_path)
        return
    if args.coverage or args.coverage_json:
        _cmd_coverage(as_json=args.coverage_json)
        return
    if args.verify_chain:
        setup_logging(config)
        _cmd_verify_chain(config)
        return
    if args.build_manifest:
        _cmd_build_manifest(config)
        return
    if args.purge_quarantine:
        _cmd_purge_quarantine(config, keep_meta=args.keep_meta)
        return
    if args.reset_chain:
        _cmd_reset_chain(config, yes=args.yes)
        return
    if args.mem_scan:
        setup_logging(config)
        _cmd_mem_scan(config)
        return

    aegis = Aegis(config_path=args.config)
    aegis.run_forever()


if __name__ == "__main__":
    main()
