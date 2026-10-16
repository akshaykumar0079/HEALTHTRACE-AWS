"""Orchestration for the user-dataset workflow: inspect -> validate -> run -> save -> repeat -> compare.

Everything is recomputed on the server from the stored upload and the submitted mapping. A client can say
which columns and methods it wants; it cannot supply results, metrics or validation outcomes.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from app.config import CONFIG_YAML_PATH, AppConfig, Settings
from app.evaluation.experiment import _git, canonical_hash
from app.evaluation.methods import METHODS
from app.evaluation.scoring import Detection
from app.privacy.redaction import Redactor
from app.research import dataset as ds_mod
from app.research.convert import Conversion, convert
from app.research.dataset import DatasetError, ParsedDataset
from app.research.engine import detect
from app.research.labels import build_intervals, score_intervals
from app.research.mapping import FIELD_SPECS, MappingSpec, spec_problems
from app.research.store import IntegrityError, NotFound, ResearchStore

SCHEMA_VERSION = 1
DEFAULT_METHODS = ("current",)
MAX_LISTED_INCIDENTS = 200

WARNING_TEXT = (
    "Research prototype. Upload only synthetic or properly de-identified data. This application is not "
    "HIPAA-certified, has not been security-reviewed for real patient data, and is not validated for clinical or "
    "production use. Uploaded files stay on this server's disk and are never sent to an external service. "
    "Identifiers are replaced by keyed pseudonyms before detection and free text is never copied, but redaction "
    "reduces accidental exposure; it does not prove a file is free of identifiers."
)

REJECT_HELP = {
    "ts_invalid": "The timestamp is missing or not ISO-8601 / epoch seconds / epoch milliseconds.",
    "ts_no_tz": "A timestamp has no timezone offset and no timezone was chosen.",
    "ts_ambiguous": "A local timestamp falls in a daylight-saving overlap; use UTC or an offset.",
    "unknown_service": "The service value is not one of the configured services. Add it under 'Value mapping'.",
    "bad_value": "A level, status, latency, priority, action or outcome value could not be interpreted. Add it under 'Value mapping' or fix the column.",
    "missing_field": "A required value is empty in this row.",
    "schema_invalid": "The row does not satisfy the event schema.",
    "pseudonym_unavailable": "An identifier is empty.",
    "column_count_mismatch": "The row has a different number of cells than the header.",
    "cell_too_long": "A cell is longer than the limit.",
    "invalid_json": "The line is not valid JSON.",
    "not_an_object": "The line is valid JSON but not an object.",
    "empty_row": "The row is empty.",
}


class ValidationFailed(Exception):
    def __init__(self, report: dict[str, Any]) -> None:
        super().__init__("validation failed")
        self.report = report


class ResearchService:
    def __init__(self, settings: Settings, config: AppConfig, redactor: Redactor) -> None:
        self.settings = settings
        self.config = config
        self.redactor = redactor
        root = settings.research_dir or (settings.db_path.parent / "research")
        self.store = ResearchStore(root)

    # -- limits and static info -----------------------------------------------------------------------

    @property
    def max_bytes(self) -> int:
        return int(self.settings.research_max_upload_mb) * 1024 * 1024

    def info(self) -> dict[str, Any]:
        return {
            "enabled": self.settings.research_enabled,
            "warning": WARNING_TEXT,
            "limits": {"max_upload_mb": self.settings.research_max_upload_mb, "max_rows": self.settings.research_max_rows,
                       "max_columns": self.settings.research_max_columns, "max_cell_chars": ds_mod.MAX_CELL_CHARS},
            "formats": sorted(ds_mod.SUPPORTED_EXTENSIONS),
            "kinds": {k: {"fields": v} for k, v in FIELD_SPECS.items()},
            "services": list(self.config.services),
            "methods": [{"id": m.id, "title": m.title, "description": m.description, "kind": m.kind,
                         "service_metric_only": m.service_only, "sensitivity": m.sensitivity}
                        for m in METHODS.values()],
            "default_methods": list(DEFAULT_METHODS),
            "retention_days": int(self.settings.retention_research_days),
            "warmup_seconds": self._warmup_seconds(),
            "external_calls": 0,
        }

    def _warmup_seconds(self) -> float:
        return float(self.config.window.size_seconds + self.config.baseline.warmup_windows * self.config.window.step_seconds)

    # -- upload / inspect ------------------------------------------------------------------------------

    def _parse(self, data: bytes, filename: Optional[str]) -> ParsedDataset:
        return ds_mod.parse_dataset(data, filename, max_rows=int(self.settings.research_max_rows),
                                    max_columns=int(self.settings.research_max_columns))

    def save_upload(self, data: bytes, filename: Optional[str], actor: str) -> dict[str, Any]:
        """Validate the file as a dataset, store the original bytes unchanged, return the preview."""
        if len(data) > self.max_bytes:
            raise DatasetError("too_large", f"The file is larger than the {self.settings.research_max_upload_mb} MB limit.")
        if not data:
            raise DatasetError("empty_file", "The file is empty.")
        fmt = ds_mod.format_for(filename)
        parsed = self._parse(data, filename)               # raises DatasetError before anything is stored
        ext = "." + ("csv" if fmt == "csv" else "jsonl")
        meta = self.store.save_upload(data, ext=ext, filename=ds_mod.safe_filename(filename), fmt=fmt, uploaded_by=actor)
        return {"upload": meta, "inspection": ds_mod.inspect_dataset(
            parsed, size_bytes=len(data), sha256=meta["id"], redactor=self.redactor)}

    def _load(self, upload_id: str) -> tuple[ParsedDataset, dict[str, Any]]:
        data, meta = self.store.read_upload(upload_id)       # verifies the hash
        return self._parse(data, meta["filename"] + meta["ext"]), meta

    def inspect(self, upload_id: str) -> dict[str, Any]:
        parsed, meta = self._load(upload_id)
        return {"upload": meta, "inspection": ds_mod.inspect_dataset(
            parsed, size_bytes=meta["size_bytes"], sha256=meta["id"], redactor=self.redactor)}

    # -- validation ------------------------------------------------------------------------------------

    def _convert(self, parsed: ParsedDataset, spec: MappingSpec) -> Conversion:
        return convert(parsed, spec, config=self.config,
                       pseudonymizer=self.store.pseudonymizer(self.settings.pseudonym_key.get_secret_value()),
                       redactor=self.redactor)

    def _report(self, parsed: ParsedDataset, spec: MappingSpec) -> tuple[dict[str, Any], Optional[Conversion]]:
        problems = spec_problems(spec, parsed.columns, self.config)
        report: dict[str, Any] = {"ok": False, "errors": list(problems), "warnings": [], "mode": "labeled" if spec.label else "unlabeled"}
        if problems:
            return report, None
        conv = self._convert(parsed, spec)
        rejected = conv.rows_total - conv.rows_accepted
        report.update({
            "rows": {"total": conv.rows_total, "accepted": conv.rows_accepted, "rejected": rejected,
                     "rejects_by_code": dict(conv.rejects),
                     "first_rows_by_code": conv.reject_rows,
                     "explanations": {c: REJECT_HELP.get(c, "") for c in conv.rejects}},
            "unmapped_values": conv.unmapped,
            "time_span": {"first": conv.first_ts.isoformat() if conv.first_ts else None,
                          "last": conv.last_ts.isoformat() if conv.last_ts else None,
                          "hours": round((conv.last_ts - conv.first_ts).total_seconds() / 3600, 4) if conv.first_ts and conv.last_ts else 0},
            "events_by_entity": dict(Counter(p.entity for p in conv.points).most_common(15)),
            "warnings": list(conv.warnings),
        })
        if spec.label is not None:
            positives = sum(1 for p in conv.points if p.positive)
            intervals = build_intervals(conv.points, scope=spec.label.scope, merge_gap_seconds=spec.label.merge_gap_seconds)
            report["labels"] = {"positive_rows": positives, "intervals": len(intervals), "rows_missing_label": conv.label_missing}
            if positives == 0:
                report["warnings"].append("No row matched the values chosen as 'anomaly'. Recall and precision cannot be "
                                          "computed; only false alarms against an all-normal ground truth can be counted.")
        if conv.rows_accepted == 0:
            report["errors"].append({"field": "rows", "code": "no_rows_accepted",
                                     "message": "No row could be read with this mapping. See the rejection reasons below."})
        elif rejected / max(conv.rows_total, 1) > 0.5:
            report["errors"].append({"field": "rows", "code": "mostly_rejected",
                                     "message": "More than half of the rows were rejected, which usually means a wrong mapping. Fix it before running."})
        elif rejected:
            report["warnings"].append(f"{rejected} of {conv.rows_total} rows were rejected and are excluded (reasons below).")
        report["ok"] = not report["errors"]
        return report, conv

    def validate(self, upload_id: str, spec: MappingSpec) -> dict[str, Any]:
        parsed, _ = self._load(upload_id)
        report, _ = self._report(parsed, spec)
        return report

    # -- running -----------------------------------------------------------------------------------------

    def _check_methods(self, methods: list[str], spec: MappingSpec) -> list[str]:
        ids = list(dict.fromkeys(methods or DEFAULT_METHODS))
        unknown = [m for m in ids if m not in METHODS]
        if unknown:
            raise ValueError(f"unknown method: {unknown[0]}")
        return ids

    def run(self, upload_id: str, spec: MappingSpec, methods: list[str], mode: str, actor: str,
            *, rerun_of: Optional[str] = None) -> dict[str, Any]:
        if mode not in ("auto", "descriptive", "labeled"):
            raise ValueError("mode must be auto, descriptive or labeled")
        if mode == "labeled" and spec.label is None:
            raise ValueError("labeled mode needs a label column and the values that mean 'anomaly'")
        effective_mode = "labeled" if (mode == "labeled" or (mode == "auto" and spec.label is not None)) else "descriptive"
        if effective_mode == "descriptive":
            spec = spec.model_copy(update={"label": None})        # labels are not used; nothing is evaluated against them
        method_ids = self._check_methods(methods, spec)

        started = time.time()
        parsed, meta = self._load(upload_id)
        report, conv = self._report(parsed, spec)
        if not report["ok"] or conv is None:
            raise ValidationFailed(report)

        span_hours = max((conv.last_ts - conv.first_ts).total_seconds() / 3600, 1 / 3600) if conv.first_ts and conv.last_ts else 0.0
        intervals = (build_intervals(conv.points, scope=spec.label.scope, merge_gap_seconds=spec.label.merge_gap_seconds)
                     if spec.label else [])
        results = []
        for mid in method_ids:
            method = METHODS[mid]
            if spec.kind != "app" and mid != "current":
                results.append({"method": mid, "applicable": False,
                                "reason": "This method only acts on service-metric (app) datasets."})
                continue
            detections = detect(conv.lines, mid)
            results.append(self._method_result(mid, detections, spec, intervals, span_hours, conv, effective_mode))

        dataset_stats = {
            "kind": spec.kind, "rows_total": conv.rows_total, "rows_accepted": conv.rows_accepted,
            "rows_rejected": conv.rows_total - conv.rows_accepted, "rejects_by_code": dict(conv.rejects),
            "first_event_at": conv.first_ts.isoformat() if conv.first_ts else None,
            "last_event_at": conv.last_ts.isoformat() if conv.last_ts else None, "span_hours": round(span_hours, 4),
            "events_by_entity": dict(Counter(p.entity for p in conv.points).most_common(15)),
            "detector_warmup_seconds": self._warmup_seconds(), "warnings": list(conv.warnings),
        }
        core = {"dataset": dataset_stats, "methods": results}
        config_part = {
            "upload_sha256": meta["id"], "mapping": spec.model_dump(mode="json"), "mode": effective_mode,
            "methods": method_ids, "config_yaml_sha256": hashlib.sha256(CONFIG_YAML_PATH.read_bytes()).hexdigest(),
            "limits": {"max_rows": int(self.settings.research_max_rows)},
        }
        fingerprint = canonical_hash(config_part)
        results_sha = canonical_hash({"config": config_part, "result": core})
        record: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "id": self.store.new_experiment_id(fingerprint),
            "created_at": datetime.now(timezone.utc).isoformat(), "created_by": actor,
            "status": "complete",
            "upload": {"sha256": meta["id"], "filename": meta["filename"], "format": meta["format"], "size_bytes": meta["size_bytes"]},
            "config": config_part, "config_fingerprint": fingerprint,
            "result": core, "results_sha256": results_sha,
            "privacy": {"raw_rows_stored_in_results": False, "identifiers": "keyed pseudonyms", "free_text_copied": False,
                        "external_calls": 0, "original_upload_modified": False},
            "disclaimer": "Research prototype. Not HIPAA-certified, not clinically validated, not for production use.",
            "run_info": {"elapsed_seconds": round(time.time() - started, 1), "git_commit": _git("rev-parse", "HEAD")},
        }
        if rerun_of:
            previous = self.store.get_experiment(rerun_of)
            record["rerun_of"] = rerun_of
            record["reproduced"] = previous["results_sha256"] == results_sha
        self.store.save_experiment(record)
        return record

    def _method_result(self, mid: str, detections: list[Detection], spec: MappingSpec, intervals: list,
                       span_hours: float, conv: Conversion, mode: str) -> dict[str, Any]:
        ordered = sorted(detections, key=lambda d: (d.first_ts, d.kind, d.entity))
        by_sev = Counter(d.peak_severity or "n/a" for d in ordered)
        by_entity = Counter(d.entity for d in ordered)
        out: dict[str, Any] = {
            "method": mid, "applicable": True, "incidents_found": len(ordered),
            "by_severity": dict(by_sev), "by_entity": dict(by_entity.most_common(15)),
            "incidents": [{"kind": d.kind, "entity": d.entity, "first_alert_at": d.first_ts.isoformat(),
                           "last_alert_at": d.last_ts.isoformat() if d.last_ts else None, "alerts": d.alert_count,
                           "peak_severity": d.peak_severity} for d in ordered[:MAX_LISTED_INCIDENTS]],
            "incidents_truncated": len(ordered) > MAX_LISTED_INCIDENTS,
        }
        if mode == "labeled" and spec.label is not None:
            scored = score_intervals(intervals, detections, span_hours=span_hours, warmup_seconds=self._warmup_seconds(),
                                     data_start=conv.first_ts)
            out["evaluation"] = {
                "mode": "labeled", "metrics_measured": True, **scored,
                "assumptions": ["The label column is treated as exhaustive ground truth: an incident outside every labelled "
                                "interval counts as a false alarm.",
                                "A hit needs the same entity and a first alert within the interval (+60 s).",
                                "The baseline is learned from this same file (in-sample); the first ~2 minutes cannot alert."],
            }
        else:
            out["evaluation"] = {
                "mode": "descriptive", "metrics_measured": False, "metrics": None,
                "note": ("No ground-truth labels were used, so precision, recall and false-alarm rate were NOT measured. "
                         "The incidents listed are what the detector reported; they have not been verified as true or false."),
            }
        return out

    def rerun(self, experiment_id: str, actor: str) -> dict[str, Any]:
        old = self.store.get_experiment(experiment_id)
        cfg = old["config"]
        spec = MappingSpec.model_validate(cfg["mapping"])
        return self.run(cfg["upload_sha256"], spec, cfg["methods"], cfg["mode"], actor, rerun_of=experiment_id)

    # -- comparison -------------------------------------------------------------------------------------

    def compare(self, a_id: str, b_id: str) -> dict[str, Any]:
        a, b = self.store.get_experiment(a_id), self.store.get_experiment(b_id)

        def head(e: dict[str, Any]) -> dict[str, Any]:
            return {"id": e["id"], "created_at": e["created_at"], "mode": e["config"]["mode"],
                    "methods": e["config"]["methods"], "upload_sha256": e["upload"]["sha256"],
                    "filename": e["upload"]["filename"], "results_sha256": e["results_sha256"]}

        def table(e: dict[str, Any]) -> dict[tuple[str, str], Any]:
            out: dict[tuple[str, str], Any] = {}
            for m in e["result"]["methods"]:
                if not m.get("applicable"):
                    continue
                out[(m["method"], "incidents_found")] = m["incidents_found"]
                ev = m["evaluation"]
                if ev.get("metrics_measured"):
                    mt = ev["metrics"]
                    for k in ("tp", "fp", "fn", "precision", "recall", "f1", "false_alarms_per_hour"):
                        out[(m["method"], k)] = mt[k]
                    out[(m["method"], "delay_median_s")] = mt["delay_s"]["median"]
            return out

        ta, tb = table(a), table(b)
        rows = [{"method": m, "metric": k, "a": ta.get((m, k)), "b": tb.get((m, k))}
                for (m, k) in sorted(set(ta) | set(tb))]
        return {
            "a": head(a), "b": head(b),
            "same_upload": a["upload"]["sha256"] == b["upload"]["sha256"],
            "same_mapping": a["config"]["mapping"] == b["config"]["mapping"],
            "same_methods": a["config"]["methods"] == b["config"]["methods"],
            "same_detector_config": a["config"]["config_yaml_sha256"] == b["config"]["config_yaml_sha256"],
            "results_identical": a["results_sha256"] == b["results_sha256"],
            "rows": rows,
            "note": ("Metrics exist only for labeled runs; an empty cell means that run did not measure it. "
                     "Comparing runs on different uploads or mappings compares different experiments."),
        }


__all__ = ["ResearchService", "ValidationFailed", "WARNING_TEXT", "NotFound", "IntegrityError", "DatasetError"]
