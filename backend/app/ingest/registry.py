"""Configured source registry (docs/ingestion.md): validates every source at
start-up and fails closed. A source whose path escapes the allowed directories,
is not a regular file, or collides with another source is a configuration error,
not a warning.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from app.config import AppConfig, Settings, SourceConfig
from app.ingest.adapters import GeneratorV1Adapter, JsonLinesAdapter
from app.ingest.pseudonym import IngestConfigError, Pseudonymizer
from app.parse.parser import Parser


@dataclass
class RegisteredSource:
    cfg: SourceConfig
    path: Path
    adapter: Any  # JsonLinesAdapter | GeneratorV1Adapter


def allowed_dirs(settings: Settings) -> list[Path]:
    dirs = [Path(settings.log_dir).resolve()]
    for raw in settings.ingest_allowed_dirs.split(","):
        raw = raw.strip()
        if raw:
            p = Path(raw)
            if not p.is_absolute():
                raise IngestConfigError("INGEST_ALLOWED_DIRS entries must be absolute paths")
            dirs.append(p.resolve())
    return dirs


def resolve_source_path(cfg: SourceConfig, settings: Settings) -> Path:
    base = Path(settings.log_dir)
    raw = Path(cfg.path)
    candidate = raw if raw.is_absolute() else base / raw
    resolved = candidate.resolve()  # follows symlinks: a link pointing outside is caught below
    if not any(resolved == d or d in resolved.parents for d in allowed_dirs(settings)):
        raise IngestConfigError(f"source {cfg.id}: path is outside the allowed directories (LOG_DIR / INGEST_ALLOWED_DIRS)")
    if resolved.exists():
        mode = resolved.stat().st_mode
        if not stat.S_ISREG(mode):
            raise IngestConfigError(f"source {cfg.id}: path is not a regular file")
    return resolved


class SourceRegistry:
    def __init__(
        self,
        app_config: AppConfig,
        settings: Settings,
        *,
        pseudonymizer: Pseudonymizer,
        redact_text: Callable[[Optional[str]], Optional[str]],
        legacy_parser: Parser,
    ) -> None:
        self.sources: dict[str, RegisteredSource] = {}
        seen_paths: dict[Path, str] = {}
        services = set(app_config.services)
        skew = timedelta(seconds=app_config.ingest.max_future_skew_seconds) if app_config.ingest.max_future_skew_seconds > 0 else None
        for cfg in app_config.ingest.sources:
            if not cfg.enabled:
                continue
            if cfg.id in self.sources:
                raise IngestConfigError(f"duplicate source id {cfg.id!r}")
            path = resolve_source_path(cfg, settings)
            if path in seen_paths:
                raise IngestConfigError(f"sources {seen_paths[path]!r} and {cfg.id!r} read the same file")
            seen_paths[path] = cfg.id
            try:
                if cfg.format == "generator_v1":
                    adapter: Any = GeneratorV1Adapter(legacy_parser, pseudonymizer, include_msg=cfg.include_msg)
                else:
                    adapter = JsonLinesAdapter(
                        cfg, pseudonymizer=pseudonymizer, redact_text=redact_text,
                        services=services, max_future_skew=skew,
                    )
            except ValueError as exc:
                raise IngestConfigError(f"source {cfg.id}: {exc}") from exc
            self.sources[cfg.id] = RegisteredSource(cfg, path, adapter)
        if not self.sources:
            raise IngestConfigError(
                "INGEST_MODE=configured but config.yaml has no enabled ingest.sources; refusing to start "
                "(nothing would be monitored)"
            )

    def adapters(self) -> dict[str, Any]:
        return {sid: s.adapter for sid, s in self.sources.items()}
