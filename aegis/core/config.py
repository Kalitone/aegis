"""
AEGIS Configuration Manager
============================
Loads YAML config, provides typed access, handles defaults.
"""

import copy
import yaml
import logging
import platform
from pathlib import Path
from typing import Any

from aegis.core.config_schema import validate_config_dict

logger = logging.getLogger("aegis.core.config")

# Sensible defaults if no config file exists
DEFAULTS = {
    "core": {
        "log_level": "INFO",
        "log_file": "logs/aegis.log",
        "log_json_file": "logs/aegis.json.log",
        "log_max_bytes": 10 * 1024 * 1024,
        "log_backup_count": 14,
        "data_dir": "data",
        "quarantine_dir": "quarantine",
        "event_db": "data/events.db",
    },
    "monitors": {
        "fim": {"enabled": True, "watch_paths": [], "poll_interval_ms": 1000},
        "process": {"enabled": True, "poll_interval_ms": 500},
        "network": {"enabled": True, "poll_interval_ms": 1000},
        "resource": {"enabled": True, "poll_interval_ms": 5000},
        "persistence": {"enabled": True, "poll_interval_ms": 300000},
        "dns": {"enabled": True, "poll_interval_seconds": 30, "sni_capture": False},
    },
    "detection": {
        "yara": {"enabled": True, "rules_dir": "rules/yara"},
        "behavioral": {"enabled": True, "rules_dir": "rules/behavioral"},
        "anomaly": {
            "enabled": True,
            "model_path": "data/anomaly_model.pkl",
            "training_period_hours": 24,
            "min_training_samples": 200,
            "contamination": 0.01,
            "auto_train": True,
        },
        "supply_chain": {
            "enabled": True,
            "typosquat_max_distance": 2,
            "malicious_db_path": "rules/supply_chain/known_malicious.json",
        },
        "sigma": {
            "enabled": False,
            "rules_dir": "rules/sigma",
            "max_rules": 0,
        },
        "threat_intel": {
            "enabled": True,
            "refresh_seconds": 3600,
            "cache_path": "data/threat_intel_cache.json",
        },
    },
    "response": {
        "auto_respond": True,
    },
    "self_protect": {
        "manifest_check": True,
        "strict": False,
        "parent_check": False,
        "watchdog": False,
    },
    "rule_updates": {
        "enabled": False,
        "interval_hours": 24,
    },
    "dashboard_web": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8765,
    },
    "alerting": {
        "webhook": {
            "url": "",
            "style": "generic",
            "min_severity": "high",
            "timeout_seconds": 5,
        },
        "toast": {
            "enabled": True,
            "min_severity": "high",
            "app_id": "AEGIS",
            "icon_path": "",
        },
        "email": {
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_password": "",
            "from_address": "aegis@localhost",
            "to_addresses": [],
            "min_severity": "critical",
        },
    },
}


class AegisConfig:
    """Configuration container with dot-notation access."""

    def __init__(self, config_path: str | None = None,
                 *, validate_strict: bool = False):
        """
        validate_strict — when True, a schema validation error raises
        SystemExit(5). When False (default), errors are logged at
        WARNING and startup continues. Use the strict mode in CI / via
        `python -m aegis --config-check`.
        """
        # Deep-copy: a shallow `dict(DEFAULTS)` shares nested dicts, so a
        # second AegisConfig (or a deep-merge from YAML) mutates the
        # module-level DEFAULTS for every later instance — visible only
        # under repeated construction (e.g. the test suite).
        self._data = copy.deepcopy(DEFAULTS)
        self._config_path = config_path
        self._platform = platform.system().lower()  # 'windows', 'linux', 'darwin'
        self._validation_errors: list[dict] = []

        if config_path and Path(config_path).exists():
            self._load(config_path)
            logger.info(f"Configuration loaded from {config_path}")
        else:
            logger.warning("No config file found, using defaults")

        self._apply_platform_defaults()
        self._validate(strict=validate_strict)

    def _load(self, path: str):
        """Load and merge YAML config over defaults."""
        with open(path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
        self._deep_merge(self._data, user_config)

    def _deep_merge(self, base: dict, override: dict):
        """Recursively merge override into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _apply_platform_defaults(self):
        """Set platform-specific defaults for watch paths etc."""
        fim = self._data["monitors"]["fim"]
        if not fim.get("watch_paths"):
            if self._platform == "windows":
                fim["watch_paths"] = [
                    r"C:\Windows\System32",
                    r"C:\Users",
                    r"C:\ProgramData",
                ]
            elif self._platform == "linux":
                fim["watch_paths"] = [
                    "/etc", "/usr/bin", "/usr/sbin",
                    "/home", "/tmp", "/var/tmp",
                ]
            elif self._platform == "darwin":
                fim["watch_paths"] = [
                    "/etc", "/usr/bin", "/usr/local/bin",
                    "/Users", "/tmp",
                ]

    def _validate(self, *, strict: bool):
        """Run the merged config through the Pydantic schema.

        Soft-fail by default — a typo logs a warning and the engine
        starts on the un-validated dict (so existing user configs
        keep working through the rollout). Strict-fail raises
        SystemExit(5) so `--config-check` and CI gates can fail.
        """
        self._validation_errors = validate_config_dict(self._data)
        if not self._validation_errors:
            return
        for err in self._validation_errors:
            logger.warning(
                f"config validation: {err['loc']}: {err['msg']} "
                f"({err['type']})"
            )
        if strict:
            raise SystemExit(5)

    @property
    def validation_errors(self) -> list[dict]:
        """Last `_validate()` call's findings. Empty when clean."""
        return list(self._validation_errors)

    def get(self, dotpath: str, default: Any = None) -> Any:
        """
        Access config via dot notation: config.get("monitors.fim.enabled")
        """
        keys = dotpath.split(".")
        value = self._data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value

    @property
    def platform(self) -> str:
        return self._platform

    @property
    def is_windows(self) -> bool:
        return self._platform == "windows"

    @property
    def is_linux(self) -> bool:
        return self._platform == "linux"

    def to_dict(self) -> dict:
        return copy.deepcopy(self._data)
