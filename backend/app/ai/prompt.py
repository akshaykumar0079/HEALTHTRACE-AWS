"""The prompt sent to a local model. It contains only the sanitised bundle."""

from __future__ import annotations

from app.ai.sanitize import Bundle

SYSTEM = """You write incident analysis for a hospital operations team from a list of FACTS.
Rules:
- Use only the FACTS provided. Never add facts, names, numbers, times or causes that are not in them.
- Every statement must list the fact ids it relies on in "evidence_refs" (copy the ids exactly as they appear as keys in FACTS).
- Hypotheses are possibilities, not findings. Phrase them with "may" or "could", and include a benign alternative when one exists.
- Facts of type related_incident are rule-based matches between incidents. Say "may be related"; never say one caused another.
- Recommendations are advice only. Never say an action has been taken.
- If the facts are not enough, set "insufficient_evidence" to true and say what is missing.
- Reply with one JSON object and nothing else, in exactly this shape:
{"summary":{"text":"","evidence_refs":[]},
 "severity_rationale":{"text":"","evidence_refs":[]},
 "hypotheses":[{"text":"","evidence_refs":[],"confidence":"low|medium"}],
 "next_steps":[{"text":"","evidence_refs":[]}],
 "insufficient_evidence":false}
- Keep each text under 300 characters. At most 3 hypotheses and 5 next steps."""


def build_prompt(bundle: Bundle) -> tuple[str, str]:
    user = ("FACTS (JSON; the keys are the fact ids; actors are aliases):\n" + bundle.prompt_json() +
            "\n\nWrite the JSON analysis now.")
    return SYSTEM, user
