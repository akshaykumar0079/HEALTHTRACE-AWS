"""The user's description of their dataset: which column is which detector field.

A :class:`MappingSpec` is data, never code, and is checked on the server against the real column list
(:func:`spec_problems`) before anything runs. The client's preview or "looks valid" is never trusted.
"""

from __future__ import annotations

from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import AppConfig
from app.ingest.timestamps import resolve_timezone

Kind = Literal["app", "audit", "auth"]

# What the user may map, per dataset kind. ``required``: must come from a column.
# ``default``: what is used when the field is not mapped (None = the field stays empty, "(row)" = row number).
FIELD_SPECS: dict[str, list[dict[str, Any]]] = {
    "app": [
        {"name": "ts", "label": "Timestamp", "required": True, "note": "ISO-8601, or epoch seconds/milliseconds."},
        {"name": "service", "label": "Service", "required": True, "can_default": True,
         "values": ["prior_auth", "eligibility", "pharmacy", "claims", "batch"],
         "note": "Must resolve to one of the configured services; map your names under 'Value mapping', "
                 "or pick one constant if the whole file is one service."},
        {"name": "level", "label": "Event level", "required": False, "values": ["INFO", "WARN", "ERROR"],
         "note": "Map this and/or Status. If only one is mapped the other is derived (status >= 500 is an error)."},
        {"name": "status", "label": "Status code", "required": False, "note": "HTTP-style 100-599. An event is an error when level is ERROR or status >= 500."},
        {"name": "latency_ms", "label": "Latency (ms)", "required": False, "default": "0",
         "note": "Optional. Without it latency anomalies cannot be detected."},
        {"name": "priority", "label": "Priority", "required": False, "can_default": True, "values": ["urgent", "routine"],
         "default": "routine", "note": "Optional. Weights patient impact."},
        {"name": "patient_id", "label": "Patient identifier", "required": False,
         "note": "Optional. Replaced by a keyed pseudonym on read; used only to count affected patients."},
        {"name": "request_id", "label": "Request identifier", "required": False, "default": "(row)",
         "note": "Optional. Replaced by a keyed pseudonym; the row number is used if not mapped."},
    ],
    "audit": [
        {"name": "ts", "label": "Timestamp", "required": True},
        {"name": "user_id", "label": "User identifier", "required": True, "note": "Replaced by a keyed pseudonym."},
        {"name": "action", "label": "Action", "required": True,
         "values": ["VIEW_RECORD", "EDIT_RECORD", "EXPORT_RECORDS", "SEARCH"], "note": "Map your action names under 'Value mapping'."},
        {"name": "patient_id", "label": "Patient identifier", "required": True, "note": "Replaced by a keyed pseudonym."},
        {"name": "role", "label": "Role", "required": False, "can_default": True, "default": "unknown"},
        {"name": "patient_region", "label": "Patient region", "required": False, "can_default": True, "default": "unknown"},
        {"name": "user_region", "label": "User region", "required": False, "can_default": True, "default": "unknown",
         "note": "Region-mismatch detection needs both regions."},
    ],
    "auth": [
        {"name": "ts", "label": "Timestamp", "required": True},
        {"name": "user_id", "label": "User identifier", "required": True, "note": "Replaced by a keyed pseudonym."},
        {"name": "outcome", "label": "Outcome", "required": True, "values": ["success", "failure"]},
        {"name": "method", "label": "Method", "required": False, "can_default": True, "default": "password"},
        {"name": "source_region", "label": "Source region", "required": False, "can_default": True, "default": "unknown"},
        {"name": "user_region", "label": "User home region", "required": False, "can_default": True, "default": "unknown"},
        {"name": "source_ip", "label": "Source IP", "required": False, "note": "Replaced by a keyed pseudonym."},
    ],
}
MAPPABLE: dict[str, set[str]] = {k: {f["name"] for f in v} for k, v in FIELD_SPECS.items()}
ENUM_FIELDS = {"service", "level", "priority", "outcome", "action"}   # fields whose values need to be canonical
MAX_VALUE_MAP_ENTRIES = 200


class LabelSpec(BaseModel):
    """Ground truth: a column whose value says whether the row belongs to a real anomaly."""

    model_config = ConfigDict(extra="forbid")

    column: str = Field(min_length=1, max_length=200)
    positive_values: list[str] = Field(min_length=1, max_length=20)
    # "entity": an anomaly belongs to the service (app) or user (audit/auth) of its rows.
    # "dataset": an anomaly is dataset-wide; any incident inside the interval counts.
    scope: Literal["entity", "dataset"] = "entity"
    merge_gap_seconds: float = Field(default=60.0, ge=0, le=3600)

    @field_validator("positive_values")
    @classmethod
    def _clean(cls, v: list[str]) -> list[str]:
        out = [str(x).strip() for x in v]
        if any(not x for x in out):
            raise ValueError("positive label values must not be empty")
        return out


class MappingSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Kind = "app"
    columns: dict[str, str] = Field(default_factory=dict)                       # canonical field -> column name
    values: dict[str, dict[str, str]] = Field(default_factory=dict)             # canonical field -> {source value -> canonical}
    defaults: dict[str, Union[str, int, float]] = Field(default_factory=dict)   # canonical field -> constant
    timezone: str = "UTC"                                                       # for timestamps without an offset
    label: Optional[LabelSpec] = None


def spec_problems(spec: MappingSpec, columns: list[str], config: AppConfig) -> list[dict[str, str]]:
    """Blocking problems with the mapping itself (not with the data). Messages never contain file content."""
    problems: list[dict[str, str]] = []

    def add(field: str, code: str, message: str) -> None:
        problems.append({"field": field, "code": code, "message": message})

    allowed = MAPPABLE[spec.kind]
    have = set(columns)
    for field, col in spec.columns.items():
        if field not in allowed:
            add(field, "unknown_field", f"'{field}' is not a field of a {spec.kind} dataset.")
        elif col not in have:
            add(field, "unknown_column", f"The column chosen for '{field}' does not exist in the file.")
    for field in list(spec.values) + list(spec.defaults):
        if field not in allowed:
            add(field, "unknown_field", f"'{field}' is not a field of a {spec.kind} dataset.")
    for field, mapping in spec.values.items():
        if field not in ENUM_FIELDS:
            add(field, "no_value_mapping", f"Value mapping is only available for: {', '.join(sorted(ENUM_FIELDS))}.")
        elif len(mapping) > MAX_VALUE_MAP_ENTRIES:
            add(field, "value_map_too_large", f"Too many value mappings for '{field}' (limit {MAX_VALUE_MAP_ENTRIES}).")
    for field, spec_info in ((f["name"], f) for f in FIELD_SPECS[spec.kind]):
        allowed_values = spec_info.get("values")
        if allowed_values and field in spec.values:
            bad = sorted({t for t in spec.values[field].values() if t not in allowed_values})
            if bad:
                add(field, "bad_mapping_target", f"Value mapping for '{field}' must map to one of: {', '.join(allowed_values)}.")
        if field in spec.defaults:
            if not spec_info.get("can_default"):
                add(field, "default_not_allowed", f"'{field}' cannot be set to a constant.")
            elif allowed_values and str(spec.defaults[field]) not in allowed_values:
                add(field, "bad_default", f"The constant for '{field}' must be one of: {', '.join(allowed_values)}.")
            elif isinstance(spec.defaults[field], str) and len(str(spec.defaults[field])) > 60:
                add(field, "bad_default", f"The constant for '{field}' is too long.")

    mapped = set(spec.columns)
    for f in FIELD_SPECS[spec.kind]:
        if f["required"] and f["name"] not in mapped:
            if f["name"] == "service" and "service" in spec.defaults:
                continue
            add(f["name"], "missing_required", f"'{f['label']}' must be mapped to a column.")
    if spec.kind == "app" and not ({"level", "status"} & mapped):
        add("level", "missing_required", "Map at least one of 'Event level' or 'Status code': without either there is no error signal.")
    if spec.kind == "app" and spec.defaults.get("service") and str(spec.defaults["service"]) not in config.services:
        add("service", "bad_default", "The constant service is not one of the configured services.")
    try:
        resolve_timezone(spec.timezone)
    except ValueError:
        add("timezone", "bad_timezone", "Unknown timezone name (use an IANA name such as UTC or America/Chicago).")
    if spec.label is not None and spec.label.column not in have:
        add("label", "unknown_column", "The label column does not exist in the file.")
    if spec.label is not None and spec.label.column in set(spec.columns.values()):
        add("label", "label_is_feature", "The label column is also mapped as a detector input, which would make the "
            "evaluation circular. Use a column that is not an input.")
    return problems
