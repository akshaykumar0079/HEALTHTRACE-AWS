"""Config loading: config.yaml (detection constants) + .env (deployment settings).

SPEC.md section 2 calls for "config.yaml + .env (pydantic-settings)". The
split is: config.yaml holds the numeric constants every detection stage
uses (criticality, baseline/anomaly/severity/hipaa/incident/window), and is
plain data (loaded once, cached); .env holds environment-specific settings
(AWS mode, paths) via pydantic-settings so they can be overridden without
editing files.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> backend/app -> backend -> repo root
# HEALTHTRACE_ROOT lets an installed copy of the package (e.g. in the Docker
# image) find config.yaml, data/ and the built frontend.
REPO_ROOT = Path(os.environ.get("HEALTHTRACE_ROOT") or Path(__file__).resolve().parents[2])
CONFIG_YAML_PATH = REPO_ROOT / "config.yaml"


class ServiceConfig(BaseModel):
    criticality: float
    label: Optional[str] = None
    depends_on: list[str] = []


class BaselineConfig(BaseModel):
    alpha: float
    warmup_windows: int
    # False judges every window against the service's all-hours baseline and
    # ignores the per-hour-of-day bucket. Only the evaluation ablation turns
    # this off (docs/evaluation.md); the product default is time-aware.
    time_aware: bool = True


class AnomalyConfig(BaseModel):
    min_std: float
    error_rate_z_threshold: float
    error_rate_min_errors: int
    error_rate_min_rate: float
    latency_z_threshold: float
    latency_min_std_ms: float


class SeverityThresholds(BaseModel):
    low_max: float
    medium_max: float
    high_max: float


class SeverityConfig(BaseModel):
    deviation_z_cap: float
    patient_factor_cap: float
    criticality_weight: float
    patient_factor_weight: float
    thresholds: SeverityThresholds


class HipaaConfig(BaseModel):
    bulk_multiplier_high: float
    bulk_multiplier_critical: float
    bulk_min_threshold: float
    export_min_threshold: float
    export_critical_records: int
    off_hours_start: str
    off_hours_end: str
    off_hours_high_records: int
    region_mismatch_medium_max: int
    # IANA zone that business hours are judged in. UTC keeps the historical
    # behaviour for callers that don't set it; config.yaml sets the real one.
    timezone: str = "UTC"
    # Minimum event-time gap before re-alerting an unchanged HIPAA pattern for
    # the same user (an escalation in severity always alerts immediately).
    realert_seconds: float = 60


class IncidentConfig(BaseModel):
    cooldown_minutes: float
    service_auto_resolve_windows: int
    hipaa_auto_resolve_minutes: float
    # A recurrence of a resolved incident's fingerprint within this many
    # minutes (of event time) reopens that incident instead of creating a new
    # one. 0 disables reopening. See docs/incident-grouping.md.
    reopen_window_minutes: float = 0.0


class AuthConfig(BaseModel):
    """Failed-logins-then-success rule (kind ``auth_suspicious_login``)."""

    failure_threshold: int = 5          # failures before a success that make it suspicious
    window_minutes: float = 10          # failures older than this are forgotten
    high_failure_multiple: int = 2      # >= threshold * this many failures raises severity
    realert_seconds: float = 60


CANONICAL_FIELDS: dict[str, tuple[str, ...]] = {
    "auth": ("ts", "event_id", "user_id", "outcome", "method", "source_region", "user_region", "source_ip"),
    "audit": ("ts", "event_id", "user_id", "role", "action", "patient_id", "patient_region", "user_region"),
    "app": ("ts", "event_id", "service", "level", "priority", "request_id", "patient_id", "status",
            "latency_ms", "msg"),
}
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "auth": ("ts", "user_id", "outcome", "source_region", "user_region"),
    "audit": ("ts", "user_id", "role", "action", "patient_id", "patient_region", "user_region"),
    "app": ("ts", "service", "level", "priority", "request_id", "status", "latency_ms", "msg"),
}


class SourceConfig(BaseModel):
    """One configured, read-only log source (docs/ingestion.md).

    ``fields`` maps a canonical field to a (dotted) path in the source's JSON;
    ``values`` maps source values to canonical ones per field (``outcome``,
    ``action``, ``service``, ``level``...); ``defaults`` supplies a constant when a
    field is absent. Anything not mapped is rejected with a reason code, never guessed."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    path: str
    format: Literal["json_lines", "generator_v1"] = "json_lines"
    kind: Optional[Literal["app", "audit", "auth"]] = None
    enabled: bool = True
    timezone: Optional[str] = None            # applied only to timestamps with no offset
    from_start: bool = False
    stalled_after_seconds: Optional[float] = None
    max_msg_chars: int = 500
    include_msg: bool = False                 # explicit opt-in for free text; off = constant placeholder
    fields: dict[str, str] = Field(default_factory=dict)
    values: dict[str, dict[str, str]] = Field(default_factory=dict)
    defaults: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_mapping(self) -> "SourceConfig":
        if self.format == "generator_v1":
            return self
        if "msg" in self.fields and not self.include_msg:
            raise ValueError(
                f"source {self.id}: 'msg' is mapped but include_msg is false. Free text is omitted by default; "
                "set include_msg: true to opt in (it is only pattern-redacted), or remove the mapping")
        if self.include_msg and "msg" not in self.fields:
            raise ValueError(f"source {self.id}: include_msg is true but 'msg' is not mapped")
        if self.kind is None:
            raise ValueError(f"source {self.id}: 'kind' (app|audit|auth) is required for json_lines")
        allowed = set(CANONICAL_FIELDS[self.kind])
        for label, names in (("fields", self.fields), ("values", self.values), ("defaults", self.defaults)):
            unknown = sorted(set(names) - allowed)
            if unknown:
                raise ValueError(f"source {self.id}: unknown canonical field(s) in {label}: {unknown}")
        optional = () if self.include_msg else ("msg",)  # omitted free text is replaced by a constant
        missing = [f for f in REQUIRED_FIELDS[self.kind]
                   if f not in self.fields and f not in self.defaults and f not in optional]
        if missing:
            raise ValueError(f"source {self.id}: no mapping or default for required field(s): {missing}")
        for must in ("ts", "user_id") if self.kind != "app" else ("ts",):
            if must not in self.fields:
                raise ValueError(f"source {self.id}: '{must}' must be mapped from the log, not defaulted")
        return self


class IngestConfig(BaseModel):
    max_future_skew_seconds: float = 300
    sources: list[SourceConfig] = Field(default_factory=list)


class WindowConfig(BaseModel):
    size_seconds: float
    step_seconds: float


class AppConfig(BaseModel):
    services: dict[str, ServiceConfig]
    priority_weight: dict[str, int]
    baseline: BaselineConfig
    anomaly: AnomalyConfig
    severity: SeverityConfig
    hipaa: HipaaConfig
    incident: IncidentConfig
    window: WindowConfig
    auth: AuthConfig = AuthConfig()
    ingest: IngestConfig = IngestConfig()


@lru_cache
def load_config(path: Path = CONFIG_YAML_PATH) -> AppConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return AppConfig.model_validate(data)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(REPO_ROOT / ".env"), env_file_encoding="utf-8", extra="ignore",
        populate_by_name=True,
    )

    aws_mode: Literal["off", "mock", "live"] = "off"
    aws_region: str = "us-east-1"
    # The original names (CLOUDWATCH_LOG_GROUP, SNS_TOPIC_ARN) are what the
    # CloudFormation template sets; the AWS_-prefixed names are accepted too.
    # If both are set, the first name listed wins.
    cloudwatch_log_group: str = Field(
        default="/medguard/alerts", validation_alias=AliasChoices("CLOUDWATCH_LOG_GROUP", "AWS_LOG_GROUP")
    )
    # Fixed CloudWatch stream name; empty = one stream per UTC day (YYYY-MM-DD).
    cloudwatch_log_stream: str = Field(
        default="", validation_alias=AliasChoices("CLOUDWATCH_LOG_STREAM", "AWS_LOG_STREAM")
    )
    sns_topic_arn: str = Field(default="", validation_alias=AliasChoices("SNS_TOPIC_ARN", "AWS_SNS_TOPIC_ARN"))
    demo_mode: bool = True
    # What feeds the log files. This project ships a synthetic generator, so the
    # honest default is "simulated"; the UI shows a SIMULATED DATA badge for it.
    data_source: Literal["simulated", "real"] = "simulated"

    # Direct email alerts for HIGH/CRITICAL incidents (Gmail SMTP by default),
    # independent of AWS. SMTP_PASSWORD must be a Gmail App Password and only
    # ever lives in the local, git-ignored .env; SecretStr keeps it out of
    # reprs and logs, and it is never returned by the API.
    email_enabled: bool = False
    # brevo: Brevo transactional email API (one API key, HTTPS, no SMTP).
    # smtp:  any SMTP server, Gmail by default (needs an App Password).
    email_provider: Literal["smtp", "brevo"] = "smtp"
    brevo_api_key: SecretStr = SecretStr("")
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_timeout_seconds: float = 15.0
    alert_email_from: str = ""  # defaults to SMTP_USERNAME (Gmail requires it to match)
    alert_email_to: str = "vasan.akxy@gmail.com"  # comma-separated
    email_min_severity: Literal["HIGH", "CRITICAL"] = "HIGH"
    email_cooldown_seconds: int = 300
    alert_email_timezone: str = "Asia/Kolkata"  # extra local time shown in emails
    dashboard_url: str = ""  # e.g. http://localhost:5173 -> adds an "Open in HEALTHTRACE" link

    # Deployment identity shown in the UI (single project/environment today).
    project_name: str = "Medicaid Pipeline"
    environment: str = "local"
    # Comma-separated browser origins allowed to call the API cross-origin.
    # Not needed when the built frontend is served by this app (same origin).
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    # When set, state-changing endpoints (ack/resolve/demo/AWS test) require
    # header X-Operator-Token with this value. Read endpoints stay open;
    # put real sign-in (e.g. ALB + Cognito) in front for production.
    operator_token: str = ""
    # Run the synthetic generator as a child process (single-service hosting
    # such as Render free has no sidecar). Off by default.
    embedded_generator: bool = False
    embedded_rate: float = 20.0
    embedded_backfill_hours: float = 2.0
    # Persist at most one window-metric row per service per N seconds (0 = every
    # window). Keeps a hosted serverless Postgres from being kept awake 24/7.
    metrics_persist_interval_seconds: float = 0.0
    # -- privacy / retention / roles (docs/privacy-and-retention.md) -----------
    redaction_enabled: bool = True
    redact_extra_fields: str = ""     # comma-separated extra keys to always redact
    redact_extra_patterns: str = ""   # comma-separated regexes replaced by [REDACTED]
    # Retention in days; 0 keeps forever. Unresolved incidents are never deleted.
    retention_metrics_hours: int = 24
    retention_evidence_days: int = 30
    retention_alerts_days: int = 90
    retention_resolved_incidents_days: int = 90
    retention_notification_attempts_days: int = 30
    retention_simulation_runs_days: int = 30
    retention_audit_days: int = 365
    retention_research_days: int = 30    # uploaded research datasets + experiment records (files); 0 = keep forever
    retention_interval_hours: int = 24   # background cleanup cadence; 0 = manual only
    # Role tokens, all sent as X-Operator-Token. viewer: read; operator
    # (OPERATOR_TOKEN): acknowledge/resolve/pin/run simulations; admin
    # (ADMIN_TOKEN): settings, retention, test notifications. With ADMIN_TOKEN
    # unset the operator token also holds admin rights (and a warning is shown).
    viewer_token: str = ""
    admin_token: str = ""
    # Require a token even to read (viewer, operator or admin).
    require_view_auth: bool = False
    # -- ingestion (docs/ingestion.md) ----------------------------------------------
    # legacy: the three synthetic files, parsed by the project's own schemas
    # (demo/test use only: NOT suitable for real logs). configured: sources from
    # config.yaml `ingest.sources`, with pseudonymization (needs PSEUDONYM_KEY).
    ingest_mode: str = "legacy"
    # event_id (default) | content (opt-in, see docs) | off
    ingest_dedupe: str = "event_id"
    # Longest accepted log line in bytes; longer lines are discarded and counted.
    ingest_max_line_bytes: int = 1 << 20
    # Secret for keyed pseudonymization of user ids, patient ids and source IPs in
    # configured mode. Required there (no fallback); never logged or stored.
    # Generate: python -c "import secrets; print(secrets.token_hex(32))"
    pseudonym_key: SecretStr = SecretStr("")
    # Extra directories (comma-separated, absolute) that configured sources may
    # read from. LOG_DIR is always allowed. Symlinks are resolved before the check.
    ingest_allowed_dirs: str = ""
    # Set to true for ONE start to accept a changed PSEUDONYM_KEY on an existing database.
    # Every pseudonym changes with the key, so old and new incidents for the same person no
    # longer correlate; without this flag a changed key stops start-up (docs/privacy-boundary.md).
    pseudonym_key_rotation_ack: bool = False
    # -- AI incident intelligence (Phase 1). Everything is off by default. The deterministic
    # insight needs none of this; a local Ollama model is an optional extra
    # (docs/ai-incident-intelligence.md).
    ai_enabled: bool = False
    ai_provider: Literal["none", "ollama"] = "none"
    ai_ollama_url: str = "http://127.0.0.1:11434"   # loopback only; any other host is refused
    ai_model: str = ""
    ai_timeout_seconds: float = 30.0
    ai_max_prompt_chars: int = 12000
    ai_max_response_chars: int = 8000
    # Incident intelligence (related / duplicate suggestions). Matching on the same pseudonymous actor is opt-in.
    incident_intel_match_actor: bool = False
    # Built frontend to serve at "/", if present.
    static_dir: Path = REPO_ROOT / "frontend" / "dist"

    # PostgreSQL URL for hosted deployments (postgres://user:pass@host/db). Empty
    # means local SQLite at DB_PATH. Never logged; only its redacted form is shown.
    database_url: str = ""
    # Refuse state-changing API calls unless OPERATOR_TOKEN is configured and sent.
    # Defaults to on in production so a forgotten token cannot leave controls open.
    require_operator_token: Optional[bool] = None

    # Absolute by default so behavior doesn't depend on the process's cwd;
    # .env overrides these with its own (also ideally absolute) paths.
    log_dir: Path = REPO_ROOT / "data" / "logs"
    # -- user-provided dataset evaluation (docs/user-datasets.md) --------------
    research_enabled: bool = True
    research_dir: Optional[Path] = None   # default: <folder of DB_PATH>/research
    research_max_upload_mb: int = 25
    research_max_rows: int = 200_000
    research_max_columns: int = 100
    db_path: Path = REPO_ROOT / "data" / "medguard.db"
    control_file: Path = REPO_ROOT / "data" / "control.json"


    @property
    def auth_required(self) -> bool:
        if self.require_operator_token is not None:
            return self.require_operator_token
        return self.environment.lower() in ("production", "prod", "staging")


@lru_cache
def get_settings() -> Settings:
    return Settings()
