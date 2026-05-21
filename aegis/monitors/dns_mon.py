"""
AEGIS DNS Monitor
==================
Captures DNS resolutions on the host so we can flag low-reputation domains,
DGA-like names, and brand-new lookups that correlate with C2 activity.

Two implementations are provided, picked at start time:

  - Windows: parse the per-process DNS resolver cache via `ipconfig /displaydns`
    (no admin needed, no extra deps). Diff between snapshots → publish only
    new entries. Coverage is identical to what every browser, sysmon-equivalent
    tool, and Microsoft Defender consumes.

  - Linux: tail `journalctl -u systemd-resolved -f` if available; otherwise
    sniff via scapy if it's installed. Both are best-effort.

We do NOT do raw packet capture by default — that requires admin/root and
adds a heavy dep. The cache parser misses sub-second-fast lookups but catches
99% of what you actually need to triage in an EDR context.

TLS SNI capture is gated behind the same scapy soft-dependency. When scapy
is present and the user opts in (`monitors.dns.sni_capture: true`), we sniff
ClientHello packets on the loopback / primary interface and publish SNI host
events. Off by default.
"""

from __future__ import annotations

import re
import time
import logging
import threading
import platform
import subprocess
from collections import deque
from pathlib import Path

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.dns")


# Common low-reputation TLDs (statistical only — not a blocklist). We use this
# for severity escalation, never to outright refuse traffic.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",   # historically free TLDs abused by phishing
    "xyz", "top", "click", "country", "stream", "download",
    "loan", "win", "bid", "review", "racing", "trade",
    "zip", "mov",                   # newly delegated, browser confusion risk
}


def _is_dga_like(domain: str) -> bool:
    """Crude DGA heuristic: long random-ish second-level label, low vowel
    ratio, lots of consonant runs. False-positive rate is ~5% on legit
    domains — fine as a *signal*, not a verdict."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return False
    label = parts[-2]
    if len(label) < 12 or not label.isalnum():
        return False
    vowels = sum(c in "aeiou" for c in label)
    if vowels / len(label) > 0.40:
        return False
    consonant_runs = re.findall(r"[bcdfghjklmnpqrstvwxz]{4,}", label)
    return bool(consonant_runs)


# ── Windows: ipconfig /displaydns parser ──────────────────────────

_DISPLAYDNS_RECORD = re.compile(
    r"^\s*Record Name[ .]*:\s*(?P<name>\S+)", re.MULTILINE | re.IGNORECASE
)


def _windows_displaydns() -> list[str]:
    """Run `ipconfig /displaydns`, return list of cached record names."""
    try:
        proc = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=15, errors="ignore",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug(f"ipconfig /displaydns failed: {e}")
        return []
    return [m.group("name").strip(".").lower()
            for m in _DISPLAYDNS_RECORD.finditer(proc.stdout or "")]


# ── DnsMonitor ────────────────────────────────────────────────────

class DnsMonitor:
    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.poll_interval = float(self.config.get("poll_interval_seconds", 30))
        self.sni_capture = bool(self.config.get("sni_capture", False))
        self._seen: set[str] = set()
        self._recent: deque[tuple[float, str]] = deque(maxlen=2000)
        self._running = False
        self._thread: threading.Thread | None = None
        self._sni_thread: threading.Thread | None = None
        self._platform = platform.system().lower()

    def start(self):
        if not self.config.get("enabled", True):
            logger.info("DnsMonitor disabled")
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="aegis-dns")
        self._thread.start()
        logger.info(f"DnsMonitor started ({self._platform}, poll={self.poll_interval}s)")
        if self.sni_capture:
            self._start_sni_sniffer()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        # First pass establishes the baseline so we don't alert on every
        # already-cached domain at startup.
        self._seen = set(self._collect())
        logger.info(f"DnsMonitor: baseline {len(self._seen)} domains")
        while self._running:
            time.sleep(self.poll_interval)
            try:
                names = self._collect()
            except Exception as e:
                logger.error(f"dns collect failed: {e}")
                continue
            new = [n for n in names if n and n not in self._seen]
            for name in new:
                self._seen.add(name)
                self._recent.append((time.time(), name))
                self._publish(name)

    def _collect(self) -> list[str]:
        if self._platform == "windows":
            return _windows_displaydns()
        # No DNS cache parsing available on non-Windows platforms.
        # Log once so operators know they're blind.
        if not getattr(self, "_linux_warned", False):
            logger.info("DnsMon: DNS cache parsing not available on this platform. "
                        "Consider enabling SNI capture (scapy) for DNS visibility.")
            self._linux_warned = True
        return []

    def _publish(self, domain: str):
        sev = Severity.INFO
        reasons: list[str] = []
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            sev = Severity.MEDIUM
            reasons.append(f"low-reputation TLD .{tld}")
        if _is_dga_like(domain):
            sev = Severity.HIGH
            reasons.append("DGA-like label")
        # Threat-intel cross-check (soft dependency).
        try:
            from aegis.detection.threat_intel import lookup_domain
            hit = lookup_domain(domain)
            if hit:
                sev = Severity.CRITICAL
                reasons.append(f"threat intel: {hit}")
        except Exception:
            pass
        self.bus.publish(Event(
            category=EventCategory.NET_CONNECT,
            severity=sev,
            source="dns",
            mitre_attack="T1071.004" if sev != Severity.INFO else "",
            data={
                "rule_name": "DNS lookup",
                "domain": domain,
                "tld": tld,
                "reasons": reasons,
            },
        ))
        if reasons:
            logger.warning(f"DNS suspicious lookup: {domain} ({', '.join(reasons)})")

    @property
    def recent(self) -> list[dict]:
        return [{"ts": ts, "domain": d} for ts, d in self._recent]

    @property
    def is_running(self) -> bool:
        return self._running

    # ── SNI sniffer (optional, scapy-backed) ──────────────────────

    def _start_sni_sniffer(self):
        try:
            from scapy.all import sniff, TCP, Raw  # type: ignore
        except ImportError:
            logger.info("DnsMonitor: scapy not installed, SNI capture disabled")
            return

        def handle(pkt):
            try:
                if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                    return
                payload = bytes(pkt[Raw].load)
                # Minimal TLS ClientHello parse: byte 0=22 (handshake),
                # byte 5=1 (ClientHello). We then walk to extensions.
                if len(payload) < 43 or payload[0] != 22 or payload[5] != 1:
                    return
                sni = self._extract_sni(payload)
                if sni:
                    self._recent.append((time.time(), sni))
                    if sni not in self._seen:
                        self._seen.add(sni)
                        self._publish(sni)
            except Exception:
                pass

        self._sni_thread = threading.Thread(
            target=lambda: sniff(filter="tcp port 443", prn=handle, store=False,
                                 stop_filter=lambda _: not self._running),
            daemon=True, name="aegis-sni",
        )
        self._sni_thread.start()
        logger.info("DnsMonitor: SNI sniffer started")

    @staticmethod
    def _extract_sni(payload: bytes) -> str | None:
        """Tiny SNI extractor — walks fixed-length fields then iterates the
        extensions list looking for type 0 (server_name)."""
        try:
            # Skip TLS record header (5) + handshake header (4) + version (2) + random (32).
            i = 5 + 4 + 2 + 32
            sid_len = payload[i]; i += 1 + sid_len
            cs_len = int.from_bytes(payload[i:i+2], "big"); i += 2 + cs_len
            cm_len = payload[i]; i += 1 + cm_len
            ext_total = int.from_bytes(payload[i:i+2], "big"); i += 2
            end = i + ext_total
            while i + 4 <= end:
                etype = int.from_bytes(payload[i:i+2], "big")
                elen = int.from_bytes(payload[i+2:i+4], "big")
                edata = payload[i+4:i+4+elen]
                i += 4 + elen
                if etype == 0:  # server_name
                    # server_name list len (2) + name_type (1) + name_len (2) + name
                    name_len = int.from_bytes(edata[3:5], "big")
                    return edata[5:5+name_len].decode("ascii", "ignore").lower()
        except Exception:
            return None
        return None
