# AI incident intelligence (Phase 1)

Each incident page shows an **AI incident insight**: a summary, why the severity is what it is,
possible causes (always labelled hypotheses), and suggested next steps. Every statement lists the
ids of the stored facts it relies on (`inc:7`, `alert:12`, `ev:30`, `rule:error_rate`, `agg:ev`).
**It recommends; it never acts.** Nothing in this feature acknowledges, resolves, mutes, notifies,
blocks or changes anything, and `executed_actions` in the API reply is always empty.

## Two paths

| Path | When | What it needs |
|---|---|---|
| **Deterministic** (always available) | Default, and the fallback for every failure | Nothing. No model, no network. |
| **Local model** (optional) | `AI_ENABLED=true`, `AI_PROVIDER=ollama`, `AI_MODEL=<name>`, and an operator presses "Ask local model" | [Ollama](https://ollama.com) running on the same machine |

Ollama is not required, not installed by this project and not contacted unless you configure it.
If it is missing, slow, unreachable, returns an error or returns an answer that fails the checks,
the dashboard shows the deterministic insight and says why (`fallback_reason`).

## What a model can see

Only a **bundle** built from an allow-list (`backend/app/ai/sanitize.py`):

* incident facts (kind, service, severity, counts, times, trend), numeric detection thresholds,
  numeric alert metrics, a handful of stored evidence records reduced to enum-like fields
  (status, latency, action, outcome, role, regions), and an aggregate of those records;
* actors as per-bundle aliases (`actor-1`), in **both** ingest modes. The stored `user_id` (raw in
  legacy mode, a pseudonym in configured mode) is never sent.

Never sent: the alert explanation text (it names the user), log `msg` text, request ids, patient
ids, IP addresses, e-mail addresses, credentials, or any field not on the allow-list. Before a
prompt is sent it is checked for any forbidden raw value and for e-mail, IP, URL, key and
SSN-shaped text; a hit cancels the call (`sanitization_failed`) and the deterministic insight is
shown. The model URL must be on the loopback interface (`127.0.0.1`, `localhost`, `::1`); other
hosts are refused. No cloud AI service is supported, and no API key is involved.

## How a model answer is checked (`validate.py`)

A claim survives only if it cites at least one real fact id and every cited id exists in the
bundle; it contains no forbidden identifier or sensitive pattern; every number, timestamp and
`actor-N` alias in it appears in the bundle; and it does not say an action has already been taken.
The summary, the severity rationale and at least one next step must survive or the whole answer is
discarded. Failing hypotheses are dropped and counted (`dropped_claims`). Confidence is set by the
code from how much evidence is stored (never "high"); the `hypothesis` label is set by the code.
Only validated model insights are stored.

## API

| Route | Role | Purpose |
|---|---|---|
| `GET /api/incidents/{id}/insight` | same as other incident reads | Stored model insight if it matches the current evidence, else the deterministic one |
| `POST /api/incidents/{id}/insight/generate` | operator | Ask the local model once (5 s minimum between runs per incident); audit-logged as `ai_insight` with a short code, never the content |
| `GET /api/ai/status` | same as other reads | Whether a model is configured |

## Storage and retention

Migration `006_ai_insights` adds one table, `ai_insights` (validated JSON, at most the 3 newest per
incident). It is deleted with a purged incident and, by age, under the existing evidence retention
rule. Migrations 1-5 are unchanged. `scripts/privacy_audit_db.py` scans the new table.

## Limits

* The deterministic hypotheses are generic possibilities, not diagnoses; they say what the stored
  evidence cannot show. A local model can only rephrase and prioritise what the bundle contains.
* A small local model can ignore the format; that is what the fallback is for. Quality has not been
  evaluated against a real model in this repository's tests, which use a fake provider and a fake
  local HTTP server.
* Phase 1 does not change detection, grouping, notifications (Brevo or AWS) or any incident state.

## Related incidents (Phase 2)

The bundle can also carry up to three deterministic related-incident matches as `rel:<id>` facts. See `docs/incident-intelligence.md`. The model may only explain them; it never finds relationships itself.
