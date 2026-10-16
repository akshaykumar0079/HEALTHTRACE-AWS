"""Write two small SYNTHETIC datasets in a foreign column layout, for trying the "Your data" page.

    python scripts/make_sample_dataset.py            # writes data/samples/

* ``sample_labeled.csv``   - an eligibility outage, with a ``Flag`` column (1 = real anomaly) you can use as labels.
* ``sample_unlabeled.csv`` - the same kind of traffic without the Flag column.

Column names deliberately differ from the project's own log format (Time, Component, Severity, HTTP, Duration_ms,
Urgency, PatientRef, ReqID), so you have to map them. Component values use names such as ``RX`` and ``Prior-Auth``
to show value mapping. Everything is generated; patient references look like ``P-000123`` and are not real.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generator import generate as gen  # noqa: E402

START = datetime(2026, 3, 10, 9, 0, 0, tzinfo=timezone.utc)
NAMES = {"eligibility": "ELIGIBILITY", "prior_auth": "Prior-Auth", "pharmacy": "RX", "claims": "claims", "batch": "batch"}
LEVELS = {"INFO": "info", "WARN": "warning", "ERROR": "error"}


def rows(seed: int, rate: float) -> list[dict]:
    rng = random.Random(seed)
    inject_start, inject_end = START + timedelta(seconds=900), START + timedelta(seconds=1080)
    events = []
    for scenario, start, seconds in ((None, START, 900), ("eligibility_outage", inject_start, 180), (None, inject_end, 420)):
        app, _, _ = gen.generate_events(scenario, seconds, rate, start, rng)
        events += app
    events.sort(key=lambda e: e["ts"])
    out = []
    for e in events:
        ts = datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
        in_outage = inject_start <= ts < inject_end and e["service"] == "eligibility"
        out.append({"Time": e["ts"], "Component": NAMES[e["service"]], "Severity": LEVELS[e["level"]], "HTTP": e["status"],
                    "Duration_ms": e["latency_ms"], "Urgency": e["priority"], "PatientRef": e["patient_id"] or "",
                    "ReqID": e["request_id"], "Flag": 1 if in_outage else 0})
    return out


def write(path: Path, data: list[dict], drop: tuple[str, ...] = ()) -> None:
    cols = [c for c in data[0] if c not in drop]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(data)
    print(f"wrote {path} ({len(data):,} rows)")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=ROOT / "data" / "samples")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--rate", type=float, default=8.0, help="events per second (default 8, about 12k rows)")
    args = p.parse_args()
    data = rows(args.seed, args.rate)
    write(args.out / "sample_labeled.csv", data)
    write(args.out / "sample_unlabeled.csv", data, drop=("Flag",))


if __name__ == "__main__":
    main()
