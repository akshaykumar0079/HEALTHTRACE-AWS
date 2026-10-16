"""Read a user-provided CSV or JSON Lines file, safely.

Rules (docs/user-datasets.md):

* only ``.csv``, ``.jsonl`` and ``.ndjson`` are accepted; the extension decides the format and the
  content is then checked (binary data, a non-UTF-8 encoding or a JSON array is refused);
* size, row, column and cell-length limits are enforced; a row that breaks one is *rejected*, never truncated;
* every message produced here names a row **number** and a reason **code**, never row content;
* nested JSON objects are flattened to dotted column names (``a.b``), arrays are ignored.

Nothing here writes a file, opens a socket or logs a value.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any, Iterator, Optional

from app.ingest.timestamps import UTC, TimestampError, normalize_ts
from app.privacy.redaction import DEFAULT_FIELDS, Redactor
from app.privacy.safe_log import scrub_text

SUPPORTED_EXTENSIONS = {".csv": "csv", ".jsonl": "jsonl", ".ndjson": "jsonl"}
MAX_CELL_CHARS = 2000
MAX_FLATTEN_DEPTH = 3
PREVIEW_ROWS = 5
PREVIEW_CELL_CHARS = 80
MASKED = "[masked: identifier or free text]"
DISTINCT_MAX = 30          # list the values of a column only when it has at most this many distinct values
DISTINCT_VALUE_CHARS = 60
PROFILE_ROWS = 5000        # rows examined for column profiles and distinct values
CSV_DELIMITERS = ",;\t|"

# Reject codes for rows (stable; surfaced in validation reports)
ROW_BAD_COLUMN_COUNT = "column_count_mismatch"
ROW_CELL_TOO_LONG = "cell_too_long"
ROW_INVALID_JSON = "invalid_json"
ROW_NOT_AN_OBJECT = "not_an_object"
ROW_EMPTY = "empty_row"


class DatasetError(ValueError):
    """The file as a whole cannot be used. ``message`` is safe to show: it never contains file content."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_filename(name: Optional[str]) -> str:
    """Base name only, pattern-scrubbed and shortened. The name is shown to the uploader; it is never trusted as a path."""
    base = PurePath((name or "upload").replace("\\", "/")).name or "upload"
    return scrub_text(base, limit=80)


def format_for(filename: Optional[str]) -> str:
    ext = PurePath((filename or "").replace("\\", "/")).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise DatasetError("unsupported_type",
                           f"Unsupported file type {ext or '(none)'!r}. Upload a .csv, .jsonl or .ndjson file.")
    return SUPPORTED_EXTENSIONS[ext]


def _decode(data: bytes) -> str:
    if b"\x00" in data[:8192]:
        raise DatasetError("binary_content", "The file looks binary (contains NUL bytes), not text.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise DatasetError("not_utf8", "The file is not valid UTF-8 text. Re-save it as UTF-8.") from None


def _flatten(obj: dict[str, Any], prefix: str = "", depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            if depth + 1 < MAX_FLATTEN_DEPTH:
                out.update(_flatten(value, f"{name}.", depth + 1))
        elif isinstance(value, list):
            continue
        else:
            out[name] = value
    return out


def _detect_delimiter(text: str) -> str:
    header = text.split("\n", 1)[0]
    counts = {d: header.count(d) for d in CSV_DELIMITERS}
    best = max(counts, key=lambda d: counts[d])
    return best if counts[best] > 0 else ","


@dataclass
class ParsedDataset:
    fmt: str
    columns: list[str]
    delimiter: Optional[str] = None
    # (row number, record or None, reject code or None). Row numbers are 1-based file lines for JSONL and
    # 1-based records after the header for CSV, as shown to the user.
    rows: list[tuple[int, Optional[dict[str, Any]], Optional[str]]] = field(default_factory=list)
    truncated: bool = False          # more rows existed than the row limit allows


def parse_dataset(data: bytes, filename: Optional[str], *, max_rows: int, max_columns: int) -> ParsedDataset:
    """Parse the whole file (up to ``max_rows`` rows). Raises :class:`DatasetError` for file-level problems."""
    fmt = format_for(filename)
    text = _decode(data)
    if not text.strip():
        raise DatasetError("empty_file", "The file is empty.")
    return _parse_csv(text, max_rows, max_columns) if fmt == "csv" else _parse_jsonl(text, max_rows, max_columns)


def _parse_csv(text: str, max_rows: int, max_columns: int) -> ParsedDataset:
    delimiter = _detect_delimiter(text)
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    try:
        header = next(reader)
    except (StopIteration, csv.Error):
        raise DatasetError("no_header", "Could not read a header row.") from None
    columns = [c.strip() for c in header]
    if not columns or any(not c for c in columns):
        raise DatasetError("bad_header", "The header row has an empty column name. Every column needs a name.")
    if len(set(columns)) != len(columns):
        raise DatasetError("duplicate_columns", "The header row repeats a column name. Column names must be unique.")
    if len(columns) > max_columns:
        raise DatasetError("too_many_columns", f"The file has {len(columns)} columns; the limit is {max_columns}.")
    out = ParsedDataset("csv", columns, delimiter)
    n = 0
    try:
        for record in reader:
            n += 1
            if n > max_rows:
                out.truncated = True
                break
            if not any(cell.strip() for cell in record):
                out.rows.append((n, None, ROW_EMPTY))
            elif len(record) != len(columns):
                out.rows.append((n, None, ROW_BAD_COLUMN_COUNT))
            elif any(len(cell) > MAX_CELL_CHARS for cell in record):
                out.rows.append((n, None, ROW_CELL_TOO_LONG))
            else:
                out.rows.append((n, dict(zip(columns, (c.strip() for c in record))), None))
    except csv.Error:
        raise DatasetError("bad_csv", f"The CSV is malformed near record {n + 1} (unterminated quote?).") from None
    return out


def _parse_jsonl(text: str, max_rows: int, max_columns: int) -> ParsedDataset:
    stripped = text.lstrip()
    if stripped.startswith("["):
        raise DatasetError("json_array", "This looks like a JSON array. Use JSON Lines: one JSON object per line.")
    out = ParsedDataset("jsonl", [])
    seen: dict[str, None] = {}
    n = 0
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        n += 1
        if n > max_rows:
            out.truncated = True
            break
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            out.rows.append((line_no, None, ROW_INVALID_JSON))
            continue
        if not isinstance(obj, dict):
            out.rows.append((line_no, None, ROW_NOT_AN_OBJECT))
            continue
        flat = _flatten(obj)
        if any(isinstance(v, str) and len(v) > MAX_CELL_CHARS for v in flat.values()):
            out.rows.append((line_no, None, ROW_CELL_TOO_LONG))
            continue
        for key in flat:
            if key not in seen:
                seen[key] = None
        if len(seen) > max_columns:
            raise DatasetError("too_many_columns", f"The file has more than {max_columns} distinct fields.")
        out.rows.append((line_no, flat, None))
    out.columns = list(seen)
    if not out.columns:
        raise DatasetError("no_records", "No usable JSON objects were found in the file.")
    return out


# -- inspection (preview + column profile) ----------------------------------------------------------------------


def _kind(values: list[Any]) -> str:
    """number | timestamp | text | empty, from non-empty sample values."""
    vals = [v for v in values if v not in (None, "")]
    if not vals:
        return "empty"

    def is_num(v: Any) -> bool:
        if isinstance(v, bool):
            return False
        if isinstance(v, (int, float)):
            return True
        try:
            float(str(v))
            return True
        except ValueError:
            return False

    def is_ts(v: Any) -> bool:
        if isinstance(v, bool):
            return False
        try:
            normalize_ts(v, default_tz=UTC)
            return True
        except TimestampError:
            return False

    ts = sum(1 for v in vals if is_ts(v))
    if ts / len(vals) >= 0.9:
        return "timestamp"
    num = sum(1 for v in vals if is_num(v))
    return "number" if num / len(vals) >= 0.9 else "text"


_NAME_HINTS = ("patient", "mrn", "user", "name", "ssn", "dob", "birth", "email", "phone", "member", "note", "message",
               "msg", "comment", "address", "descr", "ref", "account", "insur", "diagnos", "text", "ip_", "_ip")


def looks_identifying(name: str, kind: str, non_empty: int, distinct: int) -> bool:
    """A column whose cells are probably identifiers or free text: named like one, or text with mostly unique values.
    Such columns are masked in the preview and their values are never listed."""
    low = name.lower()
    if any(h in low for h in _NAME_HINTS) or low.endswith("id") or low in ("ip", "uid"):
        return True
    return kind == "text" and non_empty >= 3 and distinct / non_empty > 0.5


def sensitive_columns(columns: list[str]) -> list[str]:
    """Columns whose *name* matches a field the redactor always masks (ssn, dob, name, email, ...)."""
    return [c for c in columns if c.lower().replace(" ", "_") in DEFAULT_FIELDS]


def inspect_dataset(ds: ParsedDataset, *, size_bytes: int, sha256: str, redactor: Redactor) -> dict[str, Any]:
    """What the preview step shows. Sensitive-looking columns are masked; every cell is pattern-redacted and shortened."""
    named = set(sensitive_columns(ds.columns))
    good = [(n, rec) for n, rec, err in ds.rows if rec is not None]
    sample = good[:PROFILE_ROWS]
    rejects = Counter(err for _, rec, err in ds.rows if err)

    columns = []
    distinct: dict[str, list[str]] = {}
    masked: set[str] = set()
    for col in ds.columns:
        values = [rec.get(col) for _, rec in sample]
        non_empty = [v for v in values if v not in (None, "")]
        uniq = {str(v) for v in non_empty}
        kind = _kind(non_empty[:500])
        hide = col in named or looks_identifying(col, kind, len(non_empty), len(uniq))
        if hide:
            masked.add(col)
        columns.append({"name": col, "kind": kind, "non_empty": len(non_empty),
                        "sampled_rows": len(values), "distinct": len(uniq) if len(uniq) <= 1000 else 1000,
                        "sensitive_name": col in named, "masked_in_preview": hide})
        if not hide and 0 < len(uniq) <= DISTINCT_MAX:
            distinct[col] = sorted(scrub_text(redactor.redact_text(u) or "", limit=DISTINCT_VALUE_CHARS) for u in uniq)

    def show(col: str, value: Any) -> Any:
        if col in masked and value not in (None, ""):
            return MASKED
        if isinstance(value, str):
            return scrub_text(redactor.redact_text(value) or "", limit=PREVIEW_CELL_CHARS)
        return value

    preview = [{"row": n, **{c: show(c, rec.get(c)) for c in ds.columns}} for n, rec in good[:PREVIEW_ROWS]]
    return {
        "format": ds.fmt, "delimiter": ds.delimiter, "size_bytes": size_bytes, "sha256": sha256,
        "rows_parsed": len(ds.rows), "rows_usable": len(good), "rows_truncated_at_limit": ds.truncated,
        "row_rejects": dict(rejects), "columns": columns, "sensitive_columns": sorted(named),
        "masked_columns": sorted(masked),
        "preview_rows": preview, "distinct_values": distinct,
        "preview_note": ("The preview shows the first rows only. Columns that look like identifiers or free text are "
                         "masked, other cells are pattern-redacted and shortened. This reduces accidental exposure; it does "
                         "not prove a value is free of identifiers."),
    }


def iter_good(ds: ParsedDataset) -> Iterator[tuple[int, dict[str, Any]]]:
    for n, rec, err in ds.rows:
        if rec is not None and err is None:
            yield n, rec
