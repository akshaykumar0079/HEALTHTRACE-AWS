# HEALTH TRACE

Real-time log anomaly monitoring for healthcare pipelines (claims, prior
authorization, eligibility, pharmacy, batch). HEALTH TRACE tails growing log
files, keeps a sliding error-rate window per service, learns a baseline for
each service and hour of day, flags deviations, scores their severity by
patient impact, and pushes alerts to a live dashboard, emails HIGH and
CRITICAL incidents (Brevo email API, or any SMTP server), and can optionally ship them to
AWS (CloudWatch Logs + SNS). **AWS is not required**: the whole demo,
including email alerts, runs locally.

The detection engine is the MedGuard backend described in [SPEC.md](SPEC.md).
Only synthetic data is used: patient IDs look like `P-000123`.

```
LOG FILES -> TAILER -> SLIDING WINDOW -> BASELINE -> ANOMALY -> SEVERITY -> INCIDENT
                                                                  |-> SQLite store
                                                                  |-> WebSocket -> dashboard
                                                                  |-> Brevo email API -> email (HIGH/CRITICAL)
                                                                  '-> CloudWatch Logs / SNS (optional)
```

## Quick start (local)

Requirements: Python 3.11+, Node 20+.

```bash
python -m venv .venv
.venv/Scripts/activate            # macOS/Linux: source .venv/bin/activate
pip install -e "backend[dev]"
cd frontend && npm install && cd ..

python -m generator.generate --backfill-hours 2      # seed history (once)
python -m generator.generate --rate 30                # terminal 1: live logs
cd backend && uvicorn app.main:app --port 8010        # terminal 2: API
cd frontend && npm run dev                            # terminal 3: UI on :5173
```

Or start generator, backend and dashboard together with one command: `./start.sh`
(Ctrl+C stops everything).

Open http://localhost:5173. The dev server proxies `/api` and `/ws` to the
backend (override with `HEALTHTRACE_BACKEND=http://host:port`).

With Docker: `docker compose up --build`, then open http://localhost:8080.

## Email alerts (Brevo, no AWS)

HIGH and CRITICAL incidents are emailed to `ALERT_EMAIL_TO` (default
`vasan.akxy@gmail.com`): one email when an incident opens and one when it
escalates. Repeat alerts on an open incident, cooldown periods and muted
incidents send nothing; LOW and MEDIUM never email. Emails go out through
Brevo's free transactional email API over HTTPS. **No AWS, Gmail App
Password or SMTP port is needed.**

1. Create a free account at https://www.brevo.com and create an API key
   (Brevo menu: SMTP & API > API keys > Generate a new API key).
2. Run, from the repo root with the venv active:

   ```bash
   python scripts/setup_email.py
   ```

   Paste the API key when asked (it is hidden and never printed) and enter the
   email you signed up to Brevo with. The script writes the git-ignored `.env`
   (`EMAIL_ENABLED=true`, `EMAIL_PROVIDER=brevo`, `BREVO_API_KEY`,
   `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`) and sends one test email.
3. Start HEALTHTRACE, press `Ctrl K` / `Cmd K` in the dashboard and inject
   *Bulk PHI access* (CRITICAL) or *Urgent prior-auth failure* (HIGH). The
   email arrives within a minute (check Spam/Promotions the first time). The
   Notifications page shows sent/failed counts.

Credentials are local secrets: `.env` is git-ignored and must never be
committed. If Brevo is unreachable HEALTHTRACE logs the reason, retries up to
3 times, counts the failure on the Notifications page and keeps running.
`python scripts/test_email.py` re-sends a test email at any time.

Plain SMTP (e.g. Gmail with an App Password) still works with
`EMAIL_PROVIDER=smtp` and the `SMTP_*` settings in `.env.example`.

## Dashboard

Overview, Incidents (grouped, with severity, risk score, status, pin),
Live Events (raw log stream), Pinned, History (resolved, searchable) and
Settings (notification settings with test email). Incidents are separate from
raw events; pinning is a bookmark and never changes severity. Risk score is
the detector's score and is shown as "-" when the detection is rule-based.

## Database

Local default is SQLite (`data/medguard.db`). Set `DATABASE_URL=postgresql://...`
for PostgreSQL (hosting). Versioned, additive migrations run at start-up and
data survives restarts. Secrets are never stored in the database.

## Hosting

See [docs/deployment.md](docs/deployment.md) (Vercel + Render + Neon; prepared,
not deployed), [docs/hospital-readiness.md](docs/hospital-readiness.md) and
[docs/aws-later.md](docs/aws-later.md).

## Tests

```bash
python -m pytest backend/tests -q      # run; PostgreSQL cases need HEALTHTRACE_TEST_DATABASE_URL
cd frontend && npm run build           # typecheck + production build
```

## Demo script

1. Open the dashboard: every service is healthy.
2. Press `Ctrl K`, choose *Inject Urgent prior-auth failure*: a HIGH
   anomaly opens within seconds (and is emailed if email is enabled). Open it
   to see why it was detected.
3. Inject *Batch error spike*: a higher error rate, but it scores LOW because
   no patients are affected.
4. Inject *Bulk PHI access*: a CRITICAL HIPAA access anomaly for user U-117,
   emailed if email is enabled.
5. Inject *Recovery*: anomalies resolve on their own and MTTR is recorded.

## Documentation

- [Architecture](docs/architecture.md)
- [Backend](docs/backend.md) and the [changes made during stabilisation](docs/backend.md#stabilisation-log)
- [Real-time events](docs/realtime.md)
- [API](docs/api.md)
- [Frontend](docs/frontend.md)
- [AWS deployment](docs/aws-deployment.md)
- [AWS IAM, laptop setup and live check](docs/aws-iam.md)
- [Free deployment](docs/deployment.md)
- [Hospital-readiness foundations](docs/hospital-readiness.md)
- [Adding AWS later](docs/aws-later.md)
- [Development](docs/development.md)

## Configuration

Detection constants live in `config.yaml`. Email settings: `EMAIL_ENABLED`,
`EMAIL_PROVIDER` (brevo | smtp), `BREVO_API_KEY`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USE_TLS`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
`ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`, optional `DASHBOARD_URL` and
`ALERT_EMAIL_TIMEZONE` (default `Asia/Kolkata`). Deployment settings are
environment variables (see `.env.example`): `AWS_MODE` (off | mock | live),
`AWS_REGION`, `CLOUDWATCH_LOG_GROUP` (or `AWS_LOG_GROUP`), `CLOUDWATCH_LOG_STREAM`
(or `AWS_LOG_STREAM`), `SNS_TOPIC_ARN` (or `AWS_SNS_TOPIC_ARN`), `DEMO_MODE`,
`PROJECT_NAME`, `ENVIRONMENT`, `CORS_ORIGINS`, `OPERATOR_TOKEN`, `LOG_DIR`,
`DB_PATH`, `DATABASE_URL`, `EMAIL_MIN_SEVERITY`, `EMAIL_COOLDOWN_SECONDS`,
`DATA_SOURCE`, `REQUIRE_OPERATOR_TOKEN`, `EMBEDDED_GENERATOR`,
`METRICS_PERSIST_INTERVAL_SECONDS`.
