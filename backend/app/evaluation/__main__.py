"""``python -m app.evaluation``: run the scenario x seed x method grid and save the results."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from app.config import REPO_ROOT
from app.evaluation.experiment import DEFAULT_SEEDS, run_experiment
from app.evaluation.methods import DEFAULT_METHODS, METHODS
from app.evaluation.report import write_all
from app.simulation.scenarios import SCENARIOS


def _csv(value: str) -> tuple[str, ...]:
    return tuple(v.strip() for v in value.split(",") if v.strip())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.evaluation", description=__doc__)
    p.add_argument("--seeds", default=",".join(map(str, DEFAULT_SEEDS)),
                   help="comma-separated integer seeds (default: %(default)s)")
    p.add_argument("--scenarios", default=",".join(SCENARIOS), help="comma-separated scenario ids (default: all)")
    p.add_argument("--methods", default=",".join(DEFAULT_METHODS), help="comma-separated method ids (default: all)")
    p.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "evaluation",
                   help="output directory (default: %(default)s)")
    p.add_argument("--workers", type=int, default=max(1, min(4, (os.cpu_count() or 2) // 2)),
                   help="parallel processes; results do not depend on this (default: %(default)s)")
    p.add_argument("--quick", action="store_true", help="3 seeds (11,22,33) for a fast smoke run")
    p.add_argument("--list", action="store_true", help="list scenarios and methods, then exit")
    args = p.parse_args(argv)

    if args.list:
        print("scenarios:", ", ".join(SCENARIOS))
        for m in METHODS.values():
            print(f"method {m.id}: {m.title}")
        return 0
    try:
        seeds = (11, 22, 33) if args.quick else tuple(int(s) for s in _csv(args.seeds))
        result = run_experiment(seeds, _csv(args.scenarios), _csv(args.methods), workers=max(1, args.workers))
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    paths = write_all(result, args.out)
    print(f"results sha256 {result['results_sha256']}")
    for k, v in paths.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
