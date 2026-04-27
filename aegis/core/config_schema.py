"""
AEGIS Configuration Schema (Pydantic v2)
=========================================
Typed model of `config/aegis.yaml`. Validation happens after YAML load
+ default merge + platform defaults, so it sees the same dict the
running system will read.

Why this exists
---------------
Validating the merged config catches three classes of mistake the
free-form `dict.get(...)` accessor misses:

  1. **Typos.** `min_severity: hgih` becomes a startup warning instead
     of "alerts silently never fire."
  2. **Wrong types.** `port: "8765"` (string) becomes a clear coercion
     error instead of a TypeError two frames deep.
  3. **Unknown keys.** `mininum_severity: critical` (mis-spelt) errors
     with the field path instead of being silently ignored forever.

Validation is **soft by default** (logs warnings, continues startup)
to avoid breaking existing user configs. Operators can set
`AegisConfig(..., validate_strict=True)` or run
`python -m aegis --config-check` for a CI-friendly hard validation.

Schema policy
-------------
* Every section uses `extra="forbid"` — unknown keys are errors.
* Every field has a default that matches `config/aegis.yaml`, so a
  missing section never raises.
* Severity / log-level / webhook-style use `Literal[...]` so the
  union of legal values is enforced.
* Lists of dicts (e.g. `extra_canaries`) use `dict[str, Any]` items
  — operator data, not part of this schema's contract.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


_LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_SeverityName = Literal["info", "low", "medium", "high", "critical"]
_WebhookStyle = Literal["generic", "slack", "discord", "teams"]
_HoneyTemplate = Literal[
    "aws_creds", "ssh_key", "passwords", "wallet", "tax",
]


def _strict() -> ConfigDict:
    """Common ConfigDict for every section: refuse unknown keys."""
    return ConfigDict(extra="forbid", validate_assignment=False)


# ── core ────────────────────────────────────────────────────────────
class CoreConfig(BaseModel):
    model_config = _strict()
    log_level: _LogLevel = "INFO"
    log_file: str = "logs/aegis.log"
    log_json_file: str = "logs/aegis.json.log"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 14
    data_dir: str = "data"
    quarantine_dir: str = "quarantine"
    event_db: str = "data/events.db"
    lockfile: str = "data/aegis.pid"


# ── monitors ────────────────────────────────────────────────────────
class FimConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    watch_paths: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)
    baseline_on_start: bool = True
    hash_algorithm: str = "sha256"
    poll_interval_ms: int = 1000


class ProcessMonitorConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    poll_interval_ms: int = 500
    track_children: bool = True
    capture_environ: bool = True
    capture_cmdline: bool = True
    suspicious_parents: list[str] = Field(default_factory=list)


class NetworkMonitorConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    poll_interval_ms: int = 1000
    alert_on_new_listen: bool = True
    alert_on_new_outbound: bool = True
    trusted_ports: list[int] = Field(default_factory=list)
    suspicious_ports: list[int] = Field(default_factory=list)


class ResourceMonitorConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    poll_interval_ms: int = 5000
    cpu_threshold_percent: float = 85.0
    cpu_sustained_seconds: int = 30
    memory_growth_mb_per_min: int = 500
    disk_write_mb_per_sec: int = 100


class PersistenceMonitorConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    poll_interval_ms: int = 300_000
    poll_interval_seconds: float | None = None  # legacy alias some configs use
    baseline_path: str = "data/persistence.baseline.json"


class DnsMonitorConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    poll_interval_seconds: int = 30
    sni_capture: bool = False


class HoneyExtraCanary(BaseModel):
    model_config = _strict()
    path: str
    template: _HoneyTemplate


class HoneyMonitorConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    poll_interval_seconds: int = 60
    plant_on_start: bool = True
    plant_user_dirs: bool = True
    auto_replant: bool = False
    baseline_path: str = "data/honey.baseline.json"
    extra_canaries: list[HoneyExtraCanary] = Field(default_factory=list)


class ProcEbpfConfig(BaseModel):
    model_config = _strict()
    enabled: bool = False
    ringbuf_pages: int = 64
    poll_interval_ms: int = 100


class MonitorsConfig(BaseModel):
    model_config = _strict()
    fim: FimConfig = Field(default_factory=FimConfig)
    process: ProcessMonitorConfig = Field(default_factory=ProcessMonitorConfig)
    network: NetworkMonitorConfig = Field(default_factory=NetworkMonitorConfig)
    resource: ResourceMonitorConfig = Field(default_factory=ResourceMonitorConfig)
    persistence: PersistenceMonitorConfig = Field(default_factory=PersistenceMonitorConfig)
    dns: DnsMonitorConfig = Field(default_factory=DnsMonitorConfig)
    honey: HoneyMonitorConfig = Field(default_factory=HoneyMonitorConfig)
    proc_ebpf: ProcEbpfConfig = Field(default_factory=ProcEbpfConfig)


# ── detection ───────────────────────────────────────────────────────
class YaraMemScanConfig(BaseModel):
    model_config = _strict()
    enabled: bool = False
    interval_seconds: float = 600.0
    max_pids: int = 0


class YaraConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    rules_dir: str = "rules/yara"
    scan_on_create: bool = True
    scan_on_modify: bool = True
    scan_timeout_seconds: int = 30
    max_file_size_mb: int = 100
    exclude_paths: list[str] = Field(default_factory=list)
    exclude_extensions: list[str] = Field(default_factory=list)
    memory_scan: YaraMemScanConfig = Field(default_factory=YaraMemScanConfig)


class BehavioralConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    rules_dir: str = "rules/behavioral"
    correlation_window_seconds: int = 10


class StormBreakerConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    threshold: int = 5
    window_s: float = 300.0
    cool_off_s: float = 300.0


class AnomalyConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    model_path: str = "data/anomaly_model.pkl"
    checkpoint_path: str | None = None
    checkpoint_every: int = 50
    training_period_hours: float = 24.0
    min_training_samples: int = 200
    contamination: float = 0.01
    auto_train: bool = True
    severity: _SeverityName = "medium"
    storm_breaker: StormBreakerConfig = Field(default_factory=StormBreakerConfig)
    features: list[str] = Field(default_factory=list)


class SbomConfig(BaseModel):
    model_config = _strict()
    enabled: bool = False
    path: str = "data/sbom.cdx.json"
    interval_hours: float = 24.0
    include_npm: bool = True
    emit_on_start: bool = True


class SupplyChainConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    typosquat_max_distance: int = 2
    malicious_db_path: str = "rules/supply_chain/known_malicious.json"
    sbom: SbomConfig = Field(default_factory=SbomConfig)


class SigmaConfig(BaseModel):
    model_config = _strict()
    enabled: bool = False
    rules_dir: str = "rules/sigma"
    max_rules: int = 0


class ThreatIntelConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    refresh_seconds: int = 3600
    cache_path: str = "data/threat_intel_cache.json"


class AmsiConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    app_name: str = "AEGIS-EDR"
    max_file_size_mb: int = 16
    publish_clean_results: bool = False
    extensions: list[str] = Field(default_factory=list)


class LlmTriageConfig(BaseModel):
    model_config = _strict()
    enabled: bool = False
    model: str = "qwen-2.5-3b"
    models_dir: str = "models"
    n_ctx: int = 4096
    n_threads: int | None = None
    max_tokens_out: int = 256
    queue_size: int = 64


class DetectionConfig(BaseModel):
    model_config = _strict()
    yara: YaraConfig = Field(default_factory=YaraConfig)
    behavioral: BehavioralConfig = Field(default_factory=BehavioralConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    supply_chain: SupplyChainConfig = Field(default_factory=SupplyChainConfig)
    sigma: SigmaConfig = Field(default_factory=SigmaConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    amsi: AmsiConfig = Field(default_factory=AmsiConfig)
    llm_triage: LlmTriageConfig = Field(default_factory=LlmTriageConfig)


# ── response ────────────────────────────────────────────────────────
class HashSweepConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    time_budget_s: float = 30.0
    max_file_size_mb: int = 64
    max_depth: int = 6
    drop_zones: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)


class PersistenceHuntConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    platform: str | None = None
    roots: dict[str, Any] | None = None


class PurgeConfig(BaseModel):
    model_config = _strict()
    retention_days: float = 30.0
    require_forensic: bool = True
    secure_overwrite: bool = True


class HardeningRecheckConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    baseline_path: str | None = None
    platform: str = "auto"


class QuarantineConfig(BaseModel):
    model_config = _strict()
    allow_list_paths: list[str] = Field(default_factory=list)


class ForensicsConfig(BaseModel):
    model_config = _strict()
    retention_days: float = 30.0


class ResponseConfig(BaseModel):
    model_config = _strict()
    auto_respond: bool = True
    auto_respond_sources: dict[str, bool] = Field(default_factory=dict)
    severity_actions: dict[_SeverityName, list[str]] = Field(default_factory=dict)
    forensics: ForensicsConfig = Field(default_factory=ForensicsConfig)
    quarantine: QuarantineConfig = Field(default_factory=QuarantineConfig)
    hash_sweep: HashSweepConfig = Field(default_factory=HashSweepConfig)
    persistence_hunt: PersistenceHuntConfig = Field(default_factory=PersistenceHuntConfig)
    purge: PurgeConfig = Field(default_factory=PurgeConfig)
    hardening_recheck: HardeningRecheckConfig = Field(default_factory=HardeningRecheckConfig)


# ── dashboard ──────────────────────────────────────────────────────
class DashboardConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    refresh_interval_ms: int = 1000
    max_events_displayed: int = 50
    max_alerts_displayed: int = 20


class DashboardWebConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8765


# ── self_protect ───────────────────────────────────────────────────
class ProcessMitigationsConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    aggressive: bool = False


class SelfProtectConfig(BaseModel):
    model_config = _strict()
    manifest_check: bool = True
    strict: bool = False
    parent_check: bool = False
    watchdog: bool = False
    no_watchdog_env: bool = False
    require_attestation: bool = False
    process_mitigations: ProcessMitigationsConfig = Field(default_factory=ProcessMitigationsConfig)


# ── rule_updates ───────────────────────────────────────────────────
class RuleUpdatesConfig(BaseModel):
    model_config = _strict()
    enabled: bool = False
    interval_hours: float = 24.0


# ── alerting ───────────────────────────────────────────────────────
class OcsfSinkConfig(BaseModel):
    model_config = _strict()
    enabled: bool = False
    path: str = "logs/ocsf.json"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 7
    product_name: str = "AEGIS"
    product_vendor: str = "AEGIS"
    product_version: str = "0.2.0"
    schema_version: str = "1.1.0"


class WebhookAlerterConfig(BaseModel):
    model_config = _strict()
    url: str = ""
    style: _WebhookStyle = "generic"
    min_severity: _SeverityName = "high"
    timeout_seconds: float = 5.0


class ToastAlerterConfig(BaseModel):
    model_config = _strict()
    enabled: bool = True
    min_severity: _SeverityName = "high"
    app_id: str = "AEGIS"
    icon_path: str = ""


class EmailAlerterConfig(BaseModel):
    model_config = _strict()
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    from_address: str = "aegis@localhost"
    to_addresses: list[str] = Field(default_factory=list)
    min_severity: _SeverityName = "critical"


class AlertingConfig(BaseModel):
    model_config = _strict()
    ocsf: OcsfSinkConfig = Field(default_factory=OcsfSinkConfig)
    webhook: WebhookAlerterConfig = Field(default_factory=WebhookAlerterConfig)
    toast: ToastAlerterConfig = Field(default_factory=ToastAlerterConfig)
    email: EmailAlerterConfig = Field(default_factory=EmailAlerterConfig)


# ── top-level ──────────────────────────────────────────────────────
class AegisSettings(BaseModel):
    model_config = _strict()

    core: CoreConfig = Field(default_factory=CoreConfig)
    monitors: MonitorsConfig = Field(default_factory=MonitorsConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    dashboard_web: DashboardWebConfig = Field(default_factory=DashboardWebConfig)
    self_protect: SelfProtectConfig = Field(default_factory=SelfProtectConfig)
    rule_updates: RuleUpdatesConfig = Field(default_factory=RuleUpdatesConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)


# ── validator helper ───────────────────────────────────────────────
def validate_config_dict(data: dict) -> list[dict]:
    """Run the merged config through `AegisSettings` and return a
    flat list of `{loc, msg, type}` records.

    Returns an empty list when the config is clean. Never raises —
    `AegisConfig` decides whether to log a warning or stop the
    process based on its `validate_strict` flag.
    """
    try:
        AegisSettings.model_validate(data)
    except ValidationError as e:
        out = []
        for err in e.errors():
            loc = ".".join(str(p) for p in err.get("loc") or ())
            out.append({
                "loc": loc or "<root>",
                "msg": err.get("msg") or "validation error",
                "type": err.get("type") or "value_error",
            })
        return out
    return []


def schema_dict() -> dict:
    """Return the JSON Schema for the top-level settings model.
    Used by `python -m aegis --config-schema` for documentation."""
    return AegisSettings.model_json_schema()


__all__ = [
    "AegisSettings",
    "validate_config_dict",
    "schema_dict",
]
