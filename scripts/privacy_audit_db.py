"""Read-only scan of an EXISTING HEALTHTRACE SQLite database for rows that may hold
raw identifiers (written before configured-mode pseudonymization, or in legacy mode).

    python scripts/privacy_audit_db.py /path/to/healthtrace.db [--json]

* Opens the file read-only (SQLite ``mode=ro``); it never writes, rewrites or deletes.
* Prints COUNTS per table and column and a verdict. It never prints a cell value,
  so the report itself can be shared without leaking what it found.
* Exit status: 0 = no indicators found, 2 = indicators found, 1 = could not scan.
* "No indicators" is not proof of absence: the checks are patterns (see docs/privacy-boundary.md).
* PostgreSQL: run the equivalent counts with psql; the column list below is the same.

It does not migrate anything. The cutover procedure is in docs/privacy-boundary.md.
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

PSEUDONYM_USER = re.compile(r"^U-[0-9a-f]{12}$")
PSEUDONYM_PATIENT = re.compile(r"^P-[0-9a-f]{12}$")
PSEUDONYM_IP = re.compile(r"^ip-[0-9a-f]{12}$")

# Structured identifier columns: any non-null value that is not a pseudonym is a finding.
IDENTIFIER_COLUMNS: dict[tuple[str, str], re.Pattern[str]] = {
    ("incidents", "user_id"): PSEUDONYM_USER,
    ("alerts", "user_id"): PSEUDONYM_USER,
    ("access_stats", "user_id"): PSEUDONYM_USER,
}

# Free-text / JSON columns: count rows containing identifier-shaped text.
TEXT_COLUMNS: dict[str, list[str]] = {
    "incidents": ["fingerprint"],
    "alerts": ["explanation", "metrics_json"],
    "evidence_events": ["summary", "record_json"],
    "incident_events": ["detail"],
    "audit_log": ["target_id", "detail"],
    "notification_attempts": ["detail"],
    "simulation_runs": ["summary", "result_json"],
}
TEXT_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\w)"),
    "ssn_like": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "legacy_patient_id": re.compile(r"\bP-\d{6}\b"),
    "mrn_like": re.compile(r"(?i)\bMRN[-:# ]*\w{4,}"),
}


def scan(path: Path) -> dict[str, Any]:
    con = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        findings: list[dict[str, Any]] = []
        rows_in: dict[str, int] = {}
        for t in sorted(tables):
            if not t.startswith("sqlite_"):
                rows_in[t] = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]

        for (table, col), ok in IDENTIFIER_COLUMNS.items():
            if table not in tables:
                continue
            bad = sum(1 for (v,) in con.execute(f'SELECT "{col}" FROM "{table}" WHERE "{col}" IS NOT NULL')
                      if not ok.match(str(v)))
            if bad:
                findings.append({"table": table, "column": col, "kind": "non_pseudonym_identifier", "rows": bad})

        for table, cols in TEXT_COLUMNS.items():
            if table not in tables:
                continue
            for col in cols:
                counts = dict.fromkeys(TEXT_PATTERNS, 0)
                for (v,) in con.execute(f'SELECT "{col}" FROM "{table}" WHERE "{col}" IS NOT NULL'):
                    text = str(v)
                    for name, rx in TEXT_PATTERNS.items():
                        if rx.search(text):
                            counts[name] += 1
                for name, n in counts.items():
                    if n:
                        findings.append({"table": table, "column": col, "kind": name, "rows": n})

        meta = {}
        if "ingest_meta" in tables:
            meta = dict(con.execute("SELECT key, value FROM ingest_meta WHERE key IN "
                                    "('legacy_rows_at_cutover','key_rotated_at')").fetchall())
        return {
            "database": path.name,
            "tables": rows_in,
            "findings": findings,
            "flagged_rows_total": sum(f["rows"] for f in findings),
            "configured_mode_recorded": "ingest_meta" in tables and bool(meta or con.execute(
                "SELECT 1 FROM ingest_meta WHERE key='pseudonym_key_fingerprint'").fetchone()),
            "legacy_rows_at_cutover": meta.get("legacy_rows_at_cutover"),
            "note": "Counts only; no values are shown. Absence of findings is not proof that no identifier is present.",
        }
    finally:
        con.close()


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or not Path(args[0]).is_file():
        print("usage: privacy_audit_db.py <sqlite-file> [--json]", file=sys.stderr)
        return 1
    try:
        report = scan(Path(args[0]))
    except sqlite3.Error as exc:
        print(f"could not scan: {type(exc).__name__}", file=sys.stderr)
        return 1
    if "--json" in argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"database: {report['database']}  (read-only scan, counts only)")
        for f in report["findings"]:
            print(f"  {f['table']}.{f['column']}: {f['rows']} row(s) with {f['kind']}")
        if not report["findings"]:
            print("  no identifier-shaped values found by these checks (not proof of absence)")
        print(f"flagged rows: {report['flagged_rows_total']}")
    return 2 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
