"""
AEGIS Supply Chain Scanner
===========================
Detects malicious or typosquatted pip/npm packages.

Capabilities:
  - Typosquat detection by Levenshtein distance against top-N popular packages.
  - Known-malicious name blocklist (loaded from JSON, easily extensible).
  - Static analysis of install scripts (setup.py / package.json) for
    red-flag APIs: network calls, exec/eval, subprocess, os.system.

The scanner is usable in two modes:
  1. One-shot CLI: `python -m aegis --scan-pkg <name>` or `--scan-path <dir>`.
  2. Event-driven: subscribes to file.create under pip / npm cache paths and
     evaluates freshly-dropped packages.

When a risk is identified it publishes a detection.supply_chain event.
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Optional

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.detection.supply_chain")


# Seed list of widely used / commonly typosquatted packages. The real prod
# deployment should pull the current top-N from PyPI / npm download stats.
POPULAR_PYPI = [
    "requests", "numpy", "pandas", "scipy", "matplotlib", "pillow",
    "django", "flask", "fastapi", "uvicorn", "sqlalchemy", "pytest",
    "pyyaml", "urllib3", "cryptography", "certifi", "idna", "six",
    "setuptools", "wheel", "boto3", "botocore", "beautifulsoup4",
    "selenium", "tensorflow", "torch", "keras", "scikit-learn",
    "transformers", "openai", "anthropic", "psutil", "watchdog",
    "yara-python", "joblib", "rich", "click", "typer", "httpx",
    "aiohttp", "pydantic", "lxml", "colorama",
]

POPULAR_NPM = [
    "react", "react-dom", "vue", "angular", "lodash", "express",
    "axios", "moment", "webpack", "babel-core", "typescript",
    "eslint", "prettier", "jest", "chalk", "commander", "debug",
    "request", "mongoose", "body-parser", "cors", "dotenv", "next",
    "ts-node", "rxjs", "redux", "socket.io",
]


# Red-flag patterns in install scripts
REDFLAG_PATTERNS = [
    (r"\bexec\s*\(", "exec() call"),
    (r"\beval\s*\(", "eval() call"),
    (r"os\.system\s*\(", "os.system() shell call"),
    (r"subprocess\.(Popen|run|call|check_output)", "subprocess invocation"),
    (r"urllib(\.request)?\.urlopen", "urllib network fetch"),
    (r"requests\.(get|post)", "requests network call"),
    (r"socket\.socket", "raw socket"),
    (r"base64\.b64decode", "base64 decode (possible obfuscation)"),
    (r"__import__\s*\(", "dynamic import"),
    (r"compile\s*\(.*,\s*['\"]exec['\"]", "compiled exec block"),
    (r"child_process\.(exec|spawn)", "node child_process"),
    (r"require\s*\(\s*['\"]child_process['\"]\s*\)", "node child_process require"),
]


def levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein — small inputs, no need for a dep."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


class SupplyChainScanner:
    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config
        self.typosquat_max_distance = int(config.get("typosquat_max_distance", 2))
        self.malicious_db_path = Path(config.get(
            "malicious_db_path",
            "rules/supply_chain/known_malicious.json",
        ))
        self.popular_pypi = set(POPULAR_PYPI + list(config.get("extra_popular_pypi", [])))
        self.popular_npm = set(POPULAR_NPM + list(config.get("extra_popular_npm", [])))
        self._malicious: set[str] = set()
        self._running = False

    def start(self):
        self._load_malicious_db()
        self._running = True
        logger.info(f"Supply chain scanner started "
                    f"({len(self._malicious)} known-bad names, "
                    f"{len(self.popular_pypi)} PyPI / "
                    f"{len(self.popular_npm)} npm reference names)")

    def stop(self):
        self._running = False

    def _load_malicious_db(self):
        if not self.malicious_db_path.exists():
            logger.debug(f"No malicious DB at {self.malicious_db_path}")
            return
        try:
            data = json.loads(self.malicious_db_path.read_text())
            self._malicious = set(data.get("pypi", []) + data.get("npm", []))
        except Exception as e:
            logger.error(f"Could not load malicious DB: {e}")

    # ── Name-level checks ───────────────────────────────────

    def check_package_name(self, name: str, ecosystem: str = "pypi") -> list[dict]:
        """Return a list of findings for a package name."""
        findings = []
        name = (name or "").strip().lower()
        if not name:
            return findings

        # Known-malicious
        if name in self._malicious:
            findings.append({
                "rule": "known_malicious_package",
                "severity": Severity.CRITICAL,
                "detail": f"{name} is in the known-malicious package database",
            })

        # Typosquat
        reference = self.popular_pypi if ecosystem == "pypi" else self.popular_npm
        if name not in reference:
            for pop in reference:
                d = levenshtein(name, pop)
                if 0 < d <= self.typosquat_max_distance:
                    findings.append({
                        "rule": "typosquat",
                        "severity": Severity.HIGH,
                        "detail": (f"{name!r} is {d} edit(s) from popular "
                                   f"package {pop!r} — possible typosquat."),
                        "matched": pop,
                        "distance": d,
                    })
                    break  # one match is enough

        return findings

    # ── Content-level checks ───────────────────────────────

    def scan_install_script(self, path: Path) -> list[dict]:
        findings = []
        try:
            text = path.read_text(errors="ignore")
        except OSError as e:
            return findings
        for pattern, desc in REDFLAG_PATTERNS:
            if re.search(pattern, text):
                findings.append({
                    "rule": "install_script_redflag",
                    "severity": Severity.HIGH,
                    "detail": f"{desc} in {path.name}",
                    "pattern": pattern,
                    "file": str(path),
                })
        return findings

    def scan_package_directory(self, pkg_dir: str) -> list[dict]:
        """Scan an extracted package directory for red flags."""
        pkg_path = Path(pkg_dir)
        findings = []
        if not pkg_path.exists():
            return findings

        # Derive a candidate package name
        name = pkg_path.name.split("-")[0].lower()
        ecosystem = "npm" if (pkg_path / "package.json").exists() else "pypi"
        findings.extend([
            dict(f, source="name", package=name, ecosystem=ecosystem)
            for f in self.check_package_name(name, ecosystem)
        ])

        # setup.py, setup.cfg, pyproject.toml, package.json
        for candidate in ["setup.py", "setup.cfg", "pyproject.toml",
                          "package.json", "install.js", "preinstall.js",
                          "postinstall.js"]:
            p = pkg_path / candidate
            if p.exists() and p.is_file():
                findings.extend(self.scan_install_script(p))

        return findings

    def evaluate_and_publish(self, package: str, ecosystem: str,
                             path: Optional[str] = None) -> list[dict]:
        """Run all checks and publish events for each finding."""
        all_findings = []
        all_findings.extend([
            dict(f, package=package, ecosystem=ecosystem)
            for f in self.check_package_name(package, ecosystem)
        ])
        if path:
            all_findings.extend(self.scan_package_directory(path))

        for f in all_findings:
            sev = f.get("severity", Severity.MEDIUM)
            if not isinstance(sev, Severity):
                sev = Severity.MEDIUM
            self.bus.publish(Event(
                category=EventCategory.DETECTION_SUPPLY_CHAIN,
                severity=sev,
                source="supply_chain",
                mitre_attack="T1195.002",   # Supply Chain Compromise: Software
                data={
                    "rule_id": f.get("rule"),
                    "rule_name": f.get("rule"),
                    "description": f.get("detail", ""),
                    "package": package,
                    "ecosystem": ecosystem,
                    "path": path or "",
                    **{k: v for k, v in f.items()
                       if k not in {"severity", "rule", "detail"}},
                },
            ))
            logger.warning(f"SUPPLY CHAIN: {f.get('rule')} package={package} "
                           f"detail={f.get('detail', '')}")

        return all_findings

    @property
    def is_running(self) -> bool:
        return self._running
