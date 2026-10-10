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
from typing import Literal, Optional

import yaml
from pydantic import AliasChoices, BaseModel, Field, SecretStr
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
