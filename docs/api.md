# REST API

Base path `/api`. Endpoints marked *operator* require `X-Operator-Token` when
`OPERATOR_TOKEN` is set.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Pipeline status, throughput, event lag, replay progress, tailer offsets |
| GET | `/services` | Current state, baseline, health and dependencies per service |
| GET | `/services/{name}` | Service detail with hourly baselines, incidents and alerts |
| GET | `/metrics?service=&minutes=` | Window time series (includes the baseline in force) |
| GET | `/alerts?limit=&severity=&service=&kind=&incident_id=&user_id=` | Alert history |
| GET | `/incidents?state=&limit=` | Anomalies (incidents), newest first |
| GET | `/incidents/{id}` | Incident, lifecycle events, alerts and the detection rule |
| POST | `/incidents/{id}/ack` | Acknowledge (*operator*) |
| POST | `/incidents/{id}/resolve` | Resolve (*operator*) |
| POST | `/incidents/{id}/mute` | `{minutes}`; 0 unmutes (*operator*) |
| GET | `/logs?q=&limit=` | Search recent events. Terms are ANDed; `field:value` for service, level, status, priority, type, user, action, request_id, role, region |
| GET | `/logs/{seq}/context` | Surrounding events and related alerts |
| GET | `/hipaa/users` | Per-user rolling access picture |
| GET | `/analytics?hours=` | Trends, severity mix, MTTR, recurring fingerprints |
| GET | `/config` | Effective detection config and non-secret deployment settings |
| GET | `/aws/status` | Mode, channels, delivery counters, credential source (never keys) |
| POST | `/aws/test-connection` | Read-only reachability check (*operator*) |
| POST | `/aws/test-alert` | Send one labelled test message per channel (*operator*) |
| GET | `/demo/scenarios` | Scenario catalogue |
| POST | `/demo/inject` | `{scenario, duration_s}` when `DEMO_MODE=true` (*operator*) |

## User-provided datasets

Under `/api/research` (upload, preview, validate, run, repeat, compare): see [user-datasets.md](user-datasets.md#api).
