# Free public deployment (Vercel + Render + Neon)

**Status: prepared, NOT deployed.** Nothing in this repository has been pushed
or published, and no URL exists yet. Follow the steps below with your own
accounts. Free-tier limits were checked against the providers' pricing pages
on 2026-10-09; re-check before relying on them.

```
Browser --https--> Vercel (static React app, SPA rewrite)
   |  VITE_API_BASE_URL / VITE_WS_URL
   '--https/wss--> Render free web service (Docker: API + WebSocket + embedded synthetic generator)
                        '--> Neon free Postgres (DATABASE_URL)
```

Why this split: Render free *Postgres* expires after 30 days, so the database
is Neon's free tier instead. Render free web services support WebSockets.

## Manual steps (about 15 minutes)

1. **Neon**: create a project, copy the connection string (it already has
   `sslmode=require`). It is only ever entered as `DATABASE_URL` on Render.
2. **Render**: New > Blueprint > connect your GitHub repo (after you push it
   yourself). Render reads `render.yaml`. It will ask for the secrets marked
   `sync: false`: `DATABASE_URL`, `OPERATOR_TOKEN` (choose a long random
   string), `CORS_ORIGINS` (your Vercel origin; set it after step 3 and
   redeploy), and optionally `BREVO_API_KEY`.
3. **Vercel**: import the repo, set *Root Directory* to `frontend`, and add
   `VITE_API_BASE_URL=https://<your-render-service>.onrender.com` and
   `VITE_WS_URL=wss://<your-render-service>.onrender.com/ws`. Deploy.
4. Put the Vercel URL into Render's `CORS_ORIGINS` (no trailing slash) and
   redeploy the API.
5. Open the Vercel URL. The top bar should show LIVE and SIMULATED DATA. To
   perform actions (acknowledge, resolve, pin, settings) open the user menu >
   Operator token and enter the value you set as `OPERATOR_TOKEN`. It is kept
   in that browser tab only.

Migrations run automatically at API start-up (`schema_migrations`, additive and
idempotent). `GET /api/health` is the health check and `GET /api/status`
reports database/stream state.

## Environment variable names

Render (backend): `DATABASE_URL`, `OPERATOR_TOKEN`, `CORS_ORIGINS`,
`BREVO_API_KEY` (optional), plus fixed values in `render.yaml`: `ENVIRONMENT`,
`DATA_SOURCE`, `AWS_MODE`, `EMBEDDED_GENERATOR`, `EMBEDDED_RATE`,
`METRICS_PERSIST_INTERVAL_SECONDS`, `EMAIL_ENABLED`, `EMAIL_PROVIDER`.
`PORT` is injected by Render.
Vercel (build time, public by design): `VITE_API_BASE_URL`, `VITE_WS_URL`.
Never put `DATABASE_URL` or any key in a `VITE_` variable.

## Free-tier limits that affect this app

| Service | Limit | Effect |
|---|---|---|
| Render free web | 750 instance-hours/month; **spins down after 15 min without inbound traffic**; ~1 min cold start; ephemeral filesystem; outbound SMTP ports blocked | Detection only runs while the service is awake. After sleeping, the first visit wakes it and the dashboard shows "stale/connecting" until events flow. Logs regenerate on each start. Brevo works because it uses HTTPS, not SMTP. |
| Neon free | 0.5-1 GB storage class, ~100 compute-unit-hours/month (about 400 h at 0.25 CU), autosuspend after 5 min idle, limited egress | Continuous writes keep the DB awake, so `METRICS_PERSIST_INTERVAL_SECONDS=60` writes one metric row per service per minute. Incidents, audit and settings persist. |
| Vercel Hobby | Non-commercial use, bandwidth/build quotas | Fine for a demo; not for a commercial hospital product. |

Because Render sleeps, an external uptime pinger could keep it awake, but that
would consume the 750 hours and is not set up here. For an always-on demo run
it locally (`./start.sh` or `docker compose up`).

The embedded generator produces **synthetic** logs only (`EMBEDDED_GENERATOR=true`).
The UI labels this SIMULATED DATA. To monitor real logs you would instead mount
real log files and set `EMBEDDED_GENERATOR=false`, `DATA_SOURCE=real`.

## Security notes for the hosted demo

- HTTPS/WSS are terminated by Render and Vercel. The app trusts
  `X-Forwarded-*` (`--proxy-headers`).
- CORS only allows the origins in `CORS_ORIGINS`.
- With `ENVIRONMENT=production`, state-changing endpoints fail closed unless
  `OPERATOR_TOKEN` is configured and sent. A basic per-IP write rate limit
  (120/min) is built in.
- The database URL is logged only in redacted form; API keys are never stored
  in the database or returned by the API.
