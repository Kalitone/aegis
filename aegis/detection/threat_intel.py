"""
AEGIS Threat Intelligence
==========================
Hourly pulls from free, no-auth threat intel feeds. Builds in-memory sets of
known-bad indicators that other modules cross-reference (DNS lookups,
network connections, file hashes).

Default feeds (all free, all permissive licenses, no API keys required):

  - URLhaus (abuse.ch)            — recent malware-distribution URLs / hosts
  - Feodo Tracker (abuse.ch)      — botnet C2 IPs (Emotet, TrickBot, etc.)
  - ThreatFox (abuse.ch)          — IOC mix (IPs, domains, URLs, hashes)
  - DigitalSide OSINT             — daily IOC drops (IPs, domains, hashes)

Feed timeouts/failures are non-fatal — we keep whatever we last successfully
loaded and log the error. Sets are in-memory only (rebuilt every hour); the
on-disk cache exists so a restart doesn't immediately go blind.

Memory: ~3-5 MB per million indicators. We cap at 5 M defensively.
"""

from __future__ import annotations

import json
import time
import logging
import threading
import urllib.request
import urllib.error
from pathlib import Path

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.detection.threat_intel")

DEFAULT_FEEDS = [
    {
        "name": "urlhaus_hosts",
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "kind": "host_lines",   # one host or URL per line, # comments
    },
    {
        "name": "feodo_ips",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "kind": "ip_lines",
    },
    {
        "name": "threatfox_iocs",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "kind": "threatfox_csv",
    },
    {
        "name": "digitalside_iocs",
        "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
        "kind": "ip_lines",
    },
    {
        "name": "digitalside_domains",
        "url": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
        "kind": "host_lines",
    },
]

MAX_INDICATORS = 5_000_000

# Module-level singletons so other modules (e.g. dns_mon) can do a free
# `lookup_domain(...)` without holding a reference to the manager instance.
_BAD_DOMAINS: set[str] = set()
_BAD_IPS: set[str] = set()
_BAD_HASHES: set[str] = set()
_LOCK = threading.RLock()


# ── Public lookup helpers ─────────────────────────────────────────

def lookup_domain(domain: str) -> str | None:
    """Return source feed name if domain (or any parent) is in any feed."""
    if not domain:
        return None
    domain = domain.lower().rstrip(".")
    with _LOCK:
        if domain in _BAD_DOMAINS:
            return "domain"
        # also match parent zones — bad.example.com hits if example.com listed
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in _BAD_DOMAINS:
                return f"parent zone {parent}"
    return None


def lookup_ip(ip: str) -> str | None:
    if not ip:
        return None
    with _LOCK:
        return "ip" if ip in _BAD_IPS else None


def lookup_hash(file_hash: str) -> str | None:
    if not file_hash:
        return None
    with _LOCK:
        return "hash" if file_hash.lower() in _BAD_HASHES else None


def stats() -> dict:
    with _LOCK:
        return {"domains": len(_BAD_DOMAINS), "ips": len(_BAD_IPS),
                "hashes": len(_BAD_HASHES)}


# ── Feed parsers ──────────────────────────────────────────────────

def _parse_lines(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _parse_threatfox_csv(text: str) -> dict:
    """ThreatFox CSV: lines look like
       "ioc_id","ts","ioc","threat","malware","tags","first_seen","last_seen","reporter"
       Header lines are quoted comments starting with '#'."""
    domains, ips, hashes = set(), set(), set()
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        cols = [c.strip().strip('"') for c in raw.split(",")]
        if len(cols) < 4:
            continue
        ioc, kind = cols[2], cols[3].lower()
        if not ioc:
            continue
        if "domain" in kind:
            domains.add(ioc.lower().rstrip("."))
        elif "ip" in kind:
            # entries look like "1.2.3.4:443" — drop port
            ips.add(ioc.split(":")[0])
        elif "hash" in kind or "md5" in kind or "sha" in kind:
            hashes.add(ioc.lower())
        elif "url" in kind:
            # extract host from URL
            try:
                from urllib.parse import urlparse
                host = urlparse(ioc).hostname
                if host:
                    domains.add(host.lower())
            except Exception:
                pass
    return {"domains": domains, "ips": ips, "hashes": hashes}


def _absorb(feed_name: str, kind: str, text: str) -> dict:
    domains, ips, hashes = set(), set(), set()
    if kind == "host_lines":
        for h in _parse_lines(text):
            # URLhaus mixes URLs and bare hosts.
            if "://" in h:
                try:
                    from urllib.parse import urlparse
                    host = urlparse(h).hostname
                    if host:
                        domains.add(host.lower())
                except Exception:
                    pass
            else:
                domains.add(h.lower().rstrip("."))
    elif kind == "ip_lines":
        for ip in _parse_lines(text):
            ips.add(ip.split(":")[0])
    elif kind == "threatfox_csv":
        parsed = _parse_threatfox_csv(text)
        domains, ips, hashes = parsed["domains"], parsed["ips"], parsed["hashes"]
    return {"domains": domains, "ips": ips, "hashes": hashes}


# ── Manager ───────────────────────────────────────────────────────

class ThreatIntel:
    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.feeds = self.config.get("feeds", DEFAULT_FEEDS)
        self.refresh_seconds = float(self.config.get("refresh_seconds", 3600))
        self.cache_path = Path(self.config.get("cache_path",
                                               "data/threat_intel_cache.json"))
        self.timeout = float(self.config.get("timeout_seconds", 30))
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        if not self.config.get("enabled", True):
            logger.info("ThreatIntel disabled")
            return
        self._load_cache()
        # Subscribe to network connections + YARA detections so we can
        # cross-reference live events against the feeds.
        self.bus.subscribe(EventCategory.NET_CONNECT.value, self._on_net)
        self.bus.subscribe(EventCategory.DETECTION_YARA.value, self._on_yara)
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="aegis-threatintel")
        self._thread.start()
        logger.info(f"ThreatIntel started ({len(self.feeds)} feeds, refresh={self.refresh_seconds}s)")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _load_cache(self):
        global _BAD_DOMAINS, _BAD_IPS, _BAD_HASHES
        if not self.cache_path.exists():
            return
        try:
            data = json.loads(self.cache_path.read_text())
            with _LOCK:
                _BAD_DOMAINS = set(data.get("domains", []))
                _BAD_IPS = set(data.get("ips", []))
                _BAD_HASHES = set(data.get("hashes", []))
            logger.info(f"ThreatIntel cache loaded: {stats()}")
        except Exception as e:
            logger.warning(f"ThreatIntel cache unreadable: {e}")

    def _save_cache(self):
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with _LOCK:
                payload = {"saved_at": time.time(),
                           "domains": list(_BAD_DOMAINS),
                           "ips": list(_BAD_IPS),
                           "hashes": list(_BAD_HASHES)}
            self.cache_path.write_text(json.dumps(payload))
        except Exception as e:
            logger.warning(f"ThreatIntel cache save failed: {e}")

    def _loop(self):
        # First refresh runs immediately to populate fresh data.
        while self._running:
            self.refresh()
            slept = 0.0
            while self._running and slept < self.refresh_seconds:
                time.sleep(2.0)
                slept += 2.0

    def refresh(self) -> dict:
        """One-shot pull of every feed. Returns the per-feed status dict."""
        new_domains, new_ips, new_hashes = set(), set(), set()
        statuses: dict[str, str] = {}
        for feed in self.feeds:
            try:
                req = urllib.request.Request(
                    feed["url"], headers={"User-Agent": "AEGIS/0.2"}
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    text = resp.read().decode("utf-8", "ignore")
                parsed = _absorb(feed["name"], feed["kind"], text)
                new_domains.update(parsed["domains"])
                new_ips.update(parsed["ips"])
                new_hashes.update(parsed["hashes"])
                statuses[feed["name"]] = (
                    f"ok ({len(parsed['domains'])}d/{len(parsed['ips'])}i/"
                    f"{len(parsed['hashes'])}h)"
                )
            except (urllib.error.URLError, TimeoutError) as e:
                statuses[feed["name"]] = f"network error: {e}"
            except Exception as e:
                statuses[feed["name"]] = f"parse error: {e}"

        # Atomic swap. If every feed failed, keep prior state.
        if new_domains or new_ips or new_hashes:
            global _BAD_DOMAINS, _BAD_IPS, _BAD_HASHES
            with _LOCK:
                # cap defensively
                _BAD_DOMAINS = set(list(new_domains)[:MAX_INDICATORS])
                _BAD_IPS = set(list(new_ips)[:MAX_INDICATORS])
                _BAD_HASHES = set(list(new_hashes)[:MAX_INDICATORS])
            self._save_cache()
            logger.info(f"ThreatIntel refresh complete: {stats()}")
        else:
            logger.warning(f"ThreatIntel refresh produced no data: {statuses}")
        return statuses

    # ── live event subscribers ────────────────────────────────────

    def _on_net(self, event: Event):
        d = event.data
        # NET_CONNECT is published by both netmon (with remote_addr) and
        # dns_mon (with domain). Handle either.
        for key, lookup in (("remote_addr", lookup_ip),
                            ("domain", lookup_domain)):
            val = d.get(key)
            if not val:
                continue
            hit = lookup(val)
            if hit and event.severity != Severity.CRITICAL:
                self.bus.publish(Event(
                    category=EventCategory.DETECTION_BEHAVIORAL,
                    severity=Severity.CRITICAL,
                    source="threat_intel",
                    mitre_attack="T1071",
                    data={
                        "rule_name": "Threat-intel match",
                        "rule": "TI-001",
                        "indicator": val,
                        "indicator_type": key,
                        "intel_source": hit,
                        "source_event": d,
                    },
                ))
                logger.warning(f"THREAT INTEL HIT: {key}={val} ({hit})")

    def _on_yara(self, event: Event):
        h = event.data.get("file_hash")
        if not h:
            return
        hit = lookup_hash(h)
        if hit:
            self.bus.publish(Event(
                category=EventCategory.DETECTION_BEHAVIORAL,
                severity=Severity.CRITICAL,
                source="threat_intel",
                mitre_attack="T1027",
                data={
                    "rule_name": "Known-malicious file hash",
                    "rule": "TI-002",
                    "indicator": h,
                    "indicator_type": "hash",
                    "intel_source": hit,
                    "filepath": event.data.get("filepath", ""),
                },
            ))
            logger.warning(f"THREAT INTEL HASH HIT: {h}")

    @property
    def is_running(self) -> bool:
        return self._running


__all__ = ["ThreatIntel", "lookup_domain", "lookup_ip", "lookup_hash", "stats"]
