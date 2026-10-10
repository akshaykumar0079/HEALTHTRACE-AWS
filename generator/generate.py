"""MedGuard synthetic log generator (SPEC.md section 7).

Writes JSON-line app and audit logs. Three modes:

- ``--backfill-hours N``  write N hours of normal historical logs ending now,
  then exit. Used to warm every (service, hour_of_day) baseline before a demo.
- ``--scenario NAME --duration S``  write normal traffic for S seconds with
  NAME injected on top, then exit. Useful for tests and for exercising a
  scenario without the dashboard.
- (no flags) stream normal traffic forever in real time, polling
  data/control.json once a second for a scenario injected by the dashboard's
  POST /api/demo/inject (a later milestone).

Only synthetic data: patient IDs look like P-000123, never real PHI.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from dataclasses import dataclass
from datetime import datetime, time as dt_time, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional
from zoneinfo import ZoneInfo

import yaml

from generator.scenarios import (
    ALL_SCENARIO_NAMES,
    RECOVERY_SCENARIO,
    AccessScenario,
    AuthScenario,
    ServiceScenario,
    get_access_scenario,
    get_auth_scenario,
    get_service_scenario,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_DIR = REPO_ROOT / "data" / "logs"
DEFAULT_CONTROL_FILE = REPO_ROOT / "data" / "control.json"

SERVICES = ["prior_auth", "eligibility", "pharmacy", "claims", "batch"]
REGIONS = ["TN-North", "TN-South", "TN-East", "TN-West"]
ROLES = [
    "care_manager",
    "claims_processor",
    "pharmacist",
    "eligibility_specialist",
    "supervisor",
    "auditor",
]
NUM_USERS = 30
CONFIG_YAML_PATH = REPO_ROOT / "config.yaml"


@dataclass(frozen=True)
class BusinessHours:
    """Staff working hours, read from the same config.yaml keys the backend's
    HIPAA detector uses, so ordinary traffic never looks like off-hours access."""

    tz: ZoneInfo
    start: dt_time
    end: dt_time

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts.astimezone(self.tz).time() < self.end

    def at_local_hour(self, day: datetime, hour: int) -> datetime:
        local = day.astimezone(self.tz).replace(hour=hour, minute=0, second=0, microsecond=0)
        return local.astimezone(timezone.utc)


def load_business_hours(path: Path = CONFIG_YAML_PATH) -> BusinessHours:
    try:
        hipaa = yaml.safe_load(path.read_text(encoding="utf-8")).get("hipaa", {})
    except (OSError, AttributeError, yaml.YAMLError):
        hipaa = {}
    return BusinessHours(
        tz=ZoneInfo(hipaa.get("timezone", "UTC")),
        start=dt_time.fromisoformat(hipaa.get("off_hours_start", "07:00")),
        end=dt_time.fromisoformat(hipaa.get("off_hours_end", "21:00")),
    )

# Per-service normal-traffic shape. err_range keeps overall error rate in the
# spec's 0.5-3% band; urgent_base is each service's normal urgent/routine mix.
SERVICE_META: dict[str, dict] = {
    "prior_auth": dict(
        weight=0.25, prefix="PA", err_range=(0.01, 0.03), urgent_base=0.50,
        latency_range=(120, 450), has_patients=True,
        errors=[
            "Clinical rules engine timeout",
            "Prior auth service unavailable",
            "Downstream eligibility check failed",
            "Rules engine returned malformed response",
        ],
        oks=["Prior authorization approved", "Prior authorization request processed"],
    ),
    "eligibility": dict(
        weight=0.20, prefix="ELG", err_range=(0.005, 0.02), urgent_base=0.25,
        latency_range=(80, 350), has_patients=True,
        errors=[
            "Eligibility lookup timeout",
            "Payer system unavailable",
            "Eligibility record not found",
        ],
        oks=["Eligibility verified", "Eligibility check completed"],
    ),
    "pharmacy": dict(
        weight=0.20, prefix="RX", err_range=(0.005, 0.02), urgent_base=0.20,
        latency_range=(60, 300), has_patients=True,
        errors=[
            "Pharmacy claim rejected",
            "Drug interaction check failed",
            "Formulary lookup timeout",
        ],
        oks=["Pharmacy claim processed", "Prescription fill approved"],
    ),
    "claims": dict(
        weight=0.25, prefix="CLM", err_range=(0.01, 0.03), urgent_base=0.05,
        latency_range=(50, 300), has_patients=True,
        errors=[
            "Claim adjudication error",
            "Claims database timeout",
            "Invalid claim payload",
        ],
        oks=["Claim adjudicated", "Claim accepted for processing"],
    ),
    "batch": dict(
        weight=0.10, prefix="BATCH", err_range=(0.005, 0.015), urgent_base=0.0,
        latency_range=(200, 2000), has_patients=False,
        errors=[
            "Nightly batch job failed",
            "Batch record processing error",
            "Batch job timeout",
        ],
        oks=["Batch job completed", "Batch record processed"],
    ),
}

_ERROR_STATUSES = [500, 502, 503, 504]
_OK_STATUSES = [200, 200, 200, 201, 400, 404]
_ACTION_WEIGHTS = [("VIEW_RECORD", 0.70), ("SEARCH", 0.20), ("EDIT_RECORD", 0.08), ("EXPORT_RECORDS", 0.02)]


@dataclass
class UserProfile:
    user_id: str
    role: str
    region: str


def build_user_pool(rng: random.Random, count: int = NUM_USERS) -> list[UserProfile]:
    return [
        UserProfile(user_id=f"U-{i:03d}", role=rng.choice(ROLES), region=rng.choice(REGIONS))
        for i in range(1, count + 1)
    ]


def _scenario_user_profile(user_id: str, region: str) -> UserProfile:
    """A named individual called out by a scenario (e.g. U-117), not from the normal pool."""
    return UserProfile(user_id=user_id, role="care_manager", region=region)


def _iso(ts: datetime) -> str:
    ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _random_patient_id(rng: random.Random) -> str:
    return f"P-{rng.randint(1, 999999):06d}"


def _service_weights() -> list[float]:
    return [SERVICE_META[s]["weight"] for s in SERVICES]


def make_app_event(
    service: str,
    ts: datetime,
    rng: random.Random,
    override: Optional[ServiceScenario] = None,
) -> dict:
    """Build one app.log line (SPEC.md section 5), optionally under a ServiceScenario."""
    meta = SERVICE_META[service]
    scenario_active = override is not None and override.service == service

    error_rate = override.error_rate if scenario_active else rng.uniform(*meta["err_range"])
    is_error = rng.random() < error_rate

    urgent_base = override.urgent_fraction if (scenario_active and is_error) else meta["urgent_base"]
    priority = "urgent" if rng.random() < urgent_base else "routine"

    has_patients = override.affected_patients if scenario_active else meta["has_patients"]
    patient_id = _random_patient_id(rng) if has_patients else None

    latency_min, latency_max = meta["latency_range"]
    multiplier = override.latency_multiplier if scenario_active else 1.0
    latency_ms = rng.uniform(latency_min, latency_max) * multiplier
    if is_error:
        latency_ms *= rng.uniform(1.3, 2.5)  # timeouts run long

    if is_error:
        level = "ERROR"
        status = rng.choice(_ERROR_STATUSES)
        msg = rng.choice(meta["errors"])
    else:
        status = rng.choice(_OK_STATUSES)
        if status >= 400:
            level = "WARN"
            msg = "Client request rejected"
        elif latency_ms > latency_max:
            level = "WARN"
            msg = "Elevated latency observed"
        else:
            level = "INFO"
            msg = rng.choice(meta["oks"])

    return {
        "ts": _iso(ts),
        "type": "app",
        "service": service,
        "level": level,
        "priority": priority,
        "request_id": f"{meta['prefix']}-{rng.randint(10000, 99999)}",
        "patient_id": patient_id,
        "status": status,
        "latency_ms": max(int(latency_ms), 1),
        "msg": msg,
    }


def make_audit_event(
    user: UserProfile,
    ts: datetime,
    rng: random.Random,
    *,
    action: Optional[str] = None,
    region_mismatch: bool = False,
) -> dict:
    """Build one audit.log line (SPEC.md section 5)."""
    if action is None:
        action = rng.choices(
            [a for a, _ in _ACTION_WEIGHTS],
            weights=[w for _, w in _ACTION_WEIGHTS],
        )[0]

    patient_region = user.region
    if region_mismatch:
        other_regions = [r for r in REGIONS if r != user.region]
        patient_region = rng.choice(other_regions)

    return {
        "ts": _iso(ts),
        "type": "audit",
        "user_id": user.user_id,
        "role": user.role,
        "action": action,
        "patient_id": _random_patient_id(rng),
        "patient_region": patient_region,
        "user_region": user.region,
    }


def make_auth_event(
    user: UserProfile,
    ts: datetime,
    rng: random.Random,
    *,
    outcome: str = "success",
    source_region: Optional[str] = None,
) -> dict:
    """Build one auth.log line: a login attempt. ``source_ip`` is drawn from the
    documentation range 192.0.2.0/24 (RFC 5737), so it never points at a real host."""
    return {
        "ts": _iso(ts),
        "type": "auth",
        "user_id": user.user_id,
        "outcome": outcome,
        "method": "password",
        "source_region": source_region or user.region,
        "user_region": user.region,
        "source_ip": f"192.0.2.{rng.randint(1, 254)}",
    }


# Ordinary staff mistype a password now and then; never five times in a row.
_NORMAL_LOGIN_FAILURE_RATE = 0.03


def _poisson_times(start: datetime, duration_s: float, rate_per_sec: float, rng: random.Random) -> Iterator[datetime]:
    """Event arrival times for a Poisson process, so ~rate_per_sec events land per second on average."""
    rate_per_sec = max(rate_per_sec, 1e-6)
    t = 0.0
    while True:
        t += rng.expovariate(rate_per_sec)
        if t >= duration_s:
            return
        yield start + timedelta(seconds=t)


def generate_batch(
    scenario_name: Optional[str],
    duration_s: float,
    rate: float,
    start: datetime,
    rng: random.Random,
) -> tuple[list[dict], list[dict]]:
    """Normal traffic across all services/users for duration_s, with an optional
    named scenario (SPEC.md section 7) injected on top. Returns (app_events,
    audit_events), each sorted by ts. scenario_name=None or "recovery" means
    plain normal traffic (used for --backfill-hours and for demonstrating
    recovery). Use ``generate_events`` to also get the auth log.
    """
    app_events, audit_events, _ = generate_events(scenario_name, duration_s, rate, start, rng)
    return app_events, audit_events


def generate_events(
    scenario_name: Optional[str],
    duration_s: float,
    rate: float,
    start: datetime,
    rng: random.Random,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Like ``generate_batch`` but also returns the auth events. The auth
    events are drawn from the RNG *after* everything else, so app and audit
    output for a given seed is identical to ``generate_batch``."""
    if scenario_name not in (None, *ALL_SCENARIO_NAMES):
        raise ValueError(f"Unknown scenario: {scenario_name}")

    service_scn = get_service_scenario(scenario_name) if scenario_name else None
    access_scn = get_access_scenario(scenario_name) if scenario_name else None
    users = build_user_pool(rng)
    hours = load_business_hours()

    app_events = [
        make_app_event(rng.choices(SERVICES, weights=_service_weights())[0], ts, rng, override=service_scn)
        for ts in _poisson_times(start, duration_s, rate, rng)
    ]

    audit_rate = max(rate / 6, 0.5)  # ~30 users browsing steadily; not error-driven
    audit_events = [
        make_audit_event(rng.choice(users), ts, rng)
        for ts in _poisson_times(start, duration_s, audit_rate, rng)
        if hours.contains(ts)
    ]

    if access_scn is not None:
        target = _scenario_user_profile(access_scn.user_id, "TN-North")
        pace = access_scn.total_patients / duration_s
        for ts in _poisson_times(start, duration_s, pace, rng):
            event_ts = ts
            if access_scn.kind == "off_hours" and access_scn.hour_of_day is not None:
                elapsed = (ts - start).total_seconds()
                event_ts = hours.at_local_hour(start, access_scn.hour_of_day) + timedelta(seconds=elapsed)
            audit_events.append(
                make_audit_event(target, event_ts, rng, region_mismatch=(access_scn.kind == "region_mismatch"))
            )

    app_events.sort(key=lambda e: e["ts"])
    audit_events.sort(key=lambda e: e["ts"])

    auth_rate = max(audit_rate / 10, 0.05)
    auth_events = [
        make_auth_event(
            rng.choice(users), ts, rng,
            outcome="failure" if rng.random() < _NORMAL_LOGIN_FAILURE_RATE else "success",
        )
        for ts in _poisson_times(start, duration_s, auth_rate, rng)
        if hours.contains(ts)
    ]
    auth_scn = get_auth_scenario(scenario_name) if scenario_name else None
    if auth_scn is not None:
        auth_events += _auth_burst(auth_scn, start, duration_s, rng)
    auth_events.sort(key=lambda e: e["ts"])
    return app_events, audit_events, auth_events


def _auth_burst(scn: AuthScenario, start: datetime, duration_s: float, rng: random.Random) -> list[dict]:
    """The scenario's failures, evenly spread over the first 60% of the run,
    then one successful login from the same unfamiliar region."""
    user = _scenario_user_profile(scn.user_id, "TN-North")
    span = max(duration_s * 0.6, 1.0)
    step = span / scn.failures
    events = [
        make_auth_event(user, start + timedelta(seconds=i * step), rng, outcome="failure", source_region=scn.source_region)
        for i in range(scn.failures)
    ]
    events.append(make_auth_event(user, start + timedelta(seconds=span + step), rng, outcome="success",
                                  source_region=scn.source_region))
    return events


def _append_lines(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def _read_control(path: Path) -> Optional[tuple[dict, float]]:
    try:
        mtime = path.stat().st_mtime
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return data, mtime


def run_live(rate: float, log_dir: Path, control_file: Path, rng: random.Random) -> None:
    """Stream normal traffic forever, polling control_file once a second for a
    dashboard-injected scenario (SPEC.md section 7). Runs until interrupted.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    users = build_user_pool(rng)
    hours = load_business_hours()
    app_path = log_dir / "app.log"
    audit_path = log_dir / "audit.log"
    auth_path = log_dir / "auth.log"

    active_service: Optional[ServiceScenario] = None
    active_access: Optional[AccessScenario] = None
    active_until = 0.0
    scenario_started_at = datetime.now(timezone.utc)
    last_control_check = 0.0
    # A control file left over from before this process started is history,
    # not a new injection: without this, every generator restart replayed
    # whatever scenario the dashboard had last injected.
    existing = _read_control(control_file)
    last_control_mtime: Optional[float] = existing[1] if existing else None

    audit_rate = max(rate / 6, 0.5)
    auth_rate = max(audit_rate / 10, 0.05)
    # Scenario login events waiting for their moment: (due monotonic time, builder).
    pending_auth: list[tuple[float, str, Optional[str], str]] = []

    with app_path.open("a", encoding="utf-8") as app_f, audit_path.open("a", encoding="utf-8") as audit_f, \
            auth_path.open("a", encoding="utf-8") as auth_f:
        next_app = time.monotonic()
        next_audit = time.monotonic()
        next_auth = time.monotonic()
        next_target = time.monotonic()
        scenario_pace = 0.0

        while True:
            now_mono = time.monotonic()

            if now_mono - last_control_check >= 1.0:
                last_control_check = now_mono
                result = _read_control(control_file)
                if result is not None:
                    data, mtime = result
                    if mtime != last_control_mtime:
                        last_control_mtime = mtime
                        name = data.get("scenario")
                        duration_s = float(data.get("duration_s", 60))
                        if name in (None, RECOVERY_SCENARIO):
                            active_service = active_access = None
                            active_until = 0.0
                        else:
                            active_service = get_service_scenario(name)
                            active_access = get_access_scenario(name)
                            auth_scn = get_auth_scenario(name)
                            if auth_scn is not None:
                                span = max(duration_s * 0.6, 1.0)
                                step = span / auth_scn.failures
                                for i in range(auth_scn.failures):
                                    pending_auth.append((now_mono + i * step, auth_scn.user_id, auth_scn.source_region, "failure"))
                                pending_auth.append((now_mono + span + step, auth_scn.user_id, auth_scn.source_region, "success"))
                            active_until = now_mono + duration_s
                            scenario_started_at = datetime.now(timezone.utc)
                            if active_access is not None:
                                # The scenario user's accesses are paced to hit
                                # total_patients over the whole duration, on top
                                # of (not instead of) ordinary staff traffic.
                                scenario_pace = active_access.total_patients / max(duration_s, 1.0)
                                next_target = now_mono

            if active_until and now_mono >= active_until:
                active_service = active_access = None
                active_until = 0.0

            # Emit every event that is due, not one per loop pass: sleep() is
            # ~15ms on Windows, which capped --rate 30 at ~18 events/sec.
            if now_mono - next_app > 5.0:
                next_app = now_mono  # resumed after a stall: don't burst the backlog
            if now_mono - next_audit > 5.0:
                next_audit = now_mono
            while now_mono >= next_app:
                ts = datetime.now(timezone.utc)
                service = rng.choices(SERVICES, weights=_service_weights())[0]
                event = make_app_event(service, ts, rng, override=active_service)
                app_f.write(json.dumps(event) + "\n")
                app_f.flush()
                next_app += rng.expovariate(max(rate, 1e-6))

            while now_mono >= next_audit:
                ts = datetime.now(timezone.utc)
                if hours.contains(ts):
                    audit_f.write(json.dumps(make_audit_event(rng.choice(users), ts, rng)) + "\n")
                    audit_f.flush()
                # else: staff are off shift, no ordinary record access
                next_audit += rng.expovariate(audit_rate)

            if active_access is not None and now_mono - next_target > 5.0:
                next_target = now_mono
            if now_mono - next_auth > 5.0:
                next_auth = now_mono
            while now_mono >= next_auth:
                ts = datetime.now(timezone.utc)
                if hours.contains(ts):
                    failed = rng.random() < _NORMAL_LOGIN_FAILURE_RATE
                    auth_f.write(json.dumps(make_auth_event(
                        rng.choice(users), ts, rng, outcome="failure" if failed else "success")) + "\n")
                    auth_f.flush()
                next_auth += rng.expovariate(auth_rate)

            for due in [p for p in pending_auth if now_mono >= p[0]]:
                pending_auth.remove(due)
                _, user_id, region, outcome = due
                auth_f.write(json.dumps(make_auth_event(
                    _scenario_user_profile(user_id, "TN-North"), datetime.now(timezone.utc), rng,
                    outcome=outcome, source_region=region)) + "\n")
                auth_f.flush()

            while active_access is not None and now_mono >= next_target:
                ts = datetime.now(timezone.utc)
                if active_access.kind == "off_hours" and active_access.hour_of_day is not None:
                    elapsed = (ts - scenario_started_at).total_seconds()
                    ts = hours.at_local_hour(scenario_started_at, active_access.hour_of_day) + timedelta(seconds=elapsed)
                target = _scenario_user_profile(active_access.user_id, "TN-North")
                event = make_audit_event(target, ts, rng, region_mismatch=(active_access.kind == "region_mismatch"))
                audit_f.write(json.dumps(event) + "\n")
                audit_f.flush()
                next_target += rng.expovariate(max(scenario_pace, 1e-6))

            time.sleep(0.01)


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="MedGuard synthetic log generator (SPEC.md section 7).")
    parser.add_argument("--rate", type=float, default=30.0, help="app events/sec (spec range 20-50, default 30)")
    parser.add_argument(
        "--backfill-hours", type=float, default=None,
        help="write N hours of normal historical logs ending now, then exit",
    )
    parser.add_argument("--scenario", choices=ALL_SCENARIO_NAMES, default=None, help="inject a named scenario")
    parser.add_argument("--duration", type=float, default=60.0, help="seconds; used with --scenario")
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    parser.add_argument("--control-file", type=Path, default=DEFAULT_CONTROL_FILE)
    parser.add_argument("--seed", type=int, default=None, help="for reproducible output")
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)

    if args.backfill_hours is not None:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=args.backfill_hours)
        app_events, audit_events, auth_events = generate_events(None, args.backfill_hours * 3600, args.rate, start, rng)
        _append_lines(args.log_dir / "app.log", app_events)
        _append_lines(args.log_dir / "audit.log", audit_events)
        _append_lines(args.log_dir / "auth.log", auth_events)
        print(
            f"Backfilled {len(app_events)} app, {len(audit_events)} audit and {len(auth_events)} auth events "
            f"over {args.backfill_hours}h -> {args.log_dir}"
        )
        return

    if args.scenario is not None:
        app_events, audit_events, auth_events = generate_events(
            args.scenario, args.duration, args.rate, datetime.now(timezone.utc), rng
        )
        _append_lines(args.log_dir / "app.log", app_events)
        _append_lines(args.log_dir / "audit.log", audit_events)
        _append_lines(args.log_dir / "auth.log", auth_events)
        print(
            f"Injected '{args.scenario}' for {args.duration}s: "
            f"{len(app_events)} app, {len(audit_events)} audit, {len(auth_events)} auth events -> {args.log_dir}"
        )
        return

    print(f"Streaming ~{args.rate} events/sec to {args.log_dir} (Ctrl+C to stop)...")
    try:
        run_live(args.rate, args.log_dir, args.control_file, rng)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
