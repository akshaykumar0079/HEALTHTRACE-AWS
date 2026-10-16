# Privacy, retention, roles and audit

**No compliance is claimed.** HEALTH TRACE uses synthetic data only. These are
engineering controls, not HIPAA (or any) certification. See
[hospital-readiness.md](hospital-readiness.md).

## Redaction
Field- and pattern-based (SSN, email, phone, Luhn-valid card numbers, MRN,
bearer tokens, API keys, patient ids). Applied before storage, before display
and before email/CloudWatch/SNS. On by default (`REDACTION_ENABLED`); add
`REDACT_EXTRA_FIELDS` / `REDACT_EXTRA_PATTERNS`. An invalid pattern fails at
start-up. It reduces exposure; it does not prove a log line is identifier-free.

## Roles (header `X-Operator-Token`; WebSocket `?token=`)
| Role | Token | Can |
|---|---|---|
| viewer | `VIEWER_TOKEN` | read |
| operator | `OPERATOR_TOKEN` | + acknowledge, resolve, pin, reopen, run simulations |
| admin | `ADMIN_TOKEN` | + settings, retention, benchmark, test notifications |

Missing/invalid token -> 401; insufficient role -> 403. `REQUIRE_VIEW_AUTH`
protects reads too. **Defaults are open for local demos**; `GET /api/security/status`
and a dashboard banner warn when auth is disabled, when `ADMIN_TOKEN` is unset
(operator then holds admin), or when redaction is off (`redaction_disabled`).
Tokens are static shared secrets: put real sign-in (SSO/ALB+Cognito) in front
for anything beyond a demo.

## Audit trail
State changes (acknowledge, resolve, reopen, pin, settings, retention,
simulate) are written to the audit log (`GET /api/audit`).

## Retention
| Data | Default | Rule |
|---|---|---|
| Window metrics | 24 h | age |
| Evidence | 30 d | resolved incidents only |
| Alerts | 90 d | resolved only |
| Resolved incidents | 90 d | resolved and **unpinned** only |
| Notification attempts | 30 d | age |
| Simulation runs | 30 d | age |
| Research uploads and experiments (files, [user-datasets.md](user-datasets.md)) | 30 d | age; an upload still used by a newer experiment is kept |
| Audit log | 365 d | age |

`0` keeps forever. Open incidents are never deleted. Background cleanup every
`RETENTION_INTERVAL_HOURS` (0 = manual). `GET /api/admin/retention` previews
(dry run); `POST /api/admin/retention/run` applies (admin).

## Migrations
Versioned, additive, idempotent, run at start-up on SQLite and PostgreSQL. m003
adds timeline/evidence/simulation tables and incident grouping columns without
dropping or rewriting existing data. Back up the database before upgrading.

See also: [Privacy boundary](privacy-boundary.md) (field inventory, historical data, key rotation) and [M2 verification](M2_PRIVACY_VERIFICATION.md).
