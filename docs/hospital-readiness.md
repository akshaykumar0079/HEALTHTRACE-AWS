# Hospital-readiness foundations

HEALTH TRACE is a **demonstration with synthetic data**. This document lists
the engineering foundations that exist and what a real pilot would still need.
It makes **no compliance claim** (HIPAA, SOC 2, HITRUST or otherwise).

## In place

- **Input validation**: all mutating endpoints validate bodies (pydantic) and
  enumerations; notification settings are validated server-side (email format,
  severity HIGH/CRITICAL only, cooldown range).
- **Safe errors**: API errors return short messages, never stack traces or
  secrets; database URLs are redacted.
- **Secrets**: only in environment variables; never in the database, API
  responses, audit log or git. `.env` is git-ignored.
- **Access roles**: viewer (read-only, no token) and operator (`X-Operator-Token`).
  Fails closed in production if no token is configured.
- **Audit log**: acknowledge, investigate, resolve, pin/unpin, mute, settings
  changes and test emails are recorded (including rejected attempts), without
  secrets.
- **PHI minimisation**: logs and evidence are masked; evidence is capped per
  incident. Data is synthetic.
- **CORS allow-list, security headers, write rate-limit.**
- **Resilience**: detector keeps running if the database or notification
  provider fails; bounded queues and buffers.

## Not in place (needed before any real-data pilot)

- Per-user identity, SSO/MFA, fine-grained RBAC (today: one shared operator token).
- Encryption/retention policy, backups and a business-associate agreement with
  every vendor (Brevo, Neon, Render, Vercel are **not** HIPAA-covered on free tiers).
- Tamper-evident audit storage, centralised log shipping and alerting.
- Penetration test, threat model, vulnerability scanning in CI.
- Email should never carry PHI; today emails carry masked, synthetic metadata only.
