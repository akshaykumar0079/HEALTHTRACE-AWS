"""Orchestrates one insight: build the bundle, run the deterministic template, and
(only when explicitly enabled and configured) ask a local model, validating its
answer. Any failure at all returns the deterministic insight instead.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from app.ai.prompt import build_prompt
from app.ai.provider import Provider, ProviderError, build_provider
from app.ai.sanitize import Bundle, SanitizationError, build_bundle
from app.ai.schema import FallbackReason, Insight
from app.ai.templates import build_deterministic
from app.ai.validate import validate_model_output
from app.config import AppConfig, Settings
from app.models import Incident
from app.privacy.redaction import Redactor
from app.store.db import Store

logger = logging.getLogger(__name__)

MIN_SECONDS_BETWEEN_RUNS = 5.0


class TooSoon(RuntimeError):
    pass


class InsightService:
    def __init__(self, settings: Settings, config: AppConfig, store: Store, redactor: Redactor,
                 provider: Optional[Provider] = None) -> None:
        self.settings, self.config, self.store, self.redactor = settings, config, store, redactor
        try:
            self.provider = provider if provider is not None else build_provider(settings)
        except ValueError as exc:  # e.g. a non-loopback URL: refuse the model, keep the template
            logger.error("ai: provider disabled: %s", exc)
            self.provider = None
            self._config_error: Optional[str] = str(exc)
        else:
            self._config_error = None
        self._lock = asyncio.Lock()
        self._last_run: dict[int, float] = {}

    # -- status -------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        s = self.settings
        if not s.ai_enabled:
            reason = "ai_disabled"
        elif self._config_error:
            reason = "provider_not_configured"
        elif self.provider is None:
            reason = "provider_not_configured"
        else:
            reason = None
        return {"enabled": bool(s.ai_enabled), "provider": s.ai_provider if s.ai_enabled else "none",
                "model_configured": self.provider is not None, "deterministic_fallback": True,
                "unavailable_reason": reason}

    # -- data ---------------------------------------------------------------------

    async def bundle_for(self, incident: Incident, *, max_evidence: int = 15) -> Bundle:
        iid = incident.id
        assert iid is not None
        alerts = await self.store.list_alerts(limit=200, incident_id=iid)
        evidence = self.redactor.redact_value(await self.store.list_evidence(iid, limit=100))
        events = await self.store.list_incident_events(iid)
        return build_bundle(self.config, incident, alerts, evidence, events, redactor=self.redactor,
                            max_evidence=max_evidence, related=await self._related(incident))

    async def _related(self, incident: Incident) -> list[dict]:
        """Top deterministic matches for the model to explain. Best effort: any failure just means none."""
        try:
            from app.incidents.related import find_related

            graph = {n: list(c.depends_on) for n, c in self.config.services.items()}
            matches, _, _ = await find_related(self.store, incident, graph=graph, limit=3,
                                            match_actor=bool(self.settings.incident_intel_match_actor))
        except Exception:  # noqa: BLE001
            return []
        return [{"id": m.candidate.id, "kind": m.candidate.kind, "service": m.candidate.service,
                 "state": m.candidate.state, "severity": m.candidate.peak_severity, "score": m.score,
                 "signals": m.signals} for m in matches]

    # -- reads --------------------------------------------------------------------

    async def current(self, incident: Incident) -> dict[str, Any]:
        """What the dashboard shows: a stored model insight for exactly this evidence, else the template."""
        bundle = await self.bundle_for(incident)
        stored = await self.store.latest_ai_insight(incident.id)  # type: ignore[arg-type]
        if stored is not None and stored.bundle_hash == bundle.hash:
            return {"insight": stored, "stale_ai_available": False, "ai": self.status()}
        return {"insight": build_deterministic(bundle), "stale_ai_available": stored is not None, "ai": self.status()}

    # -- model run ----------------------------------------------------------------

    def _fallback(self, bundle: Bundle, reason: FallbackReason) -> Insight:
        insight = build_deterministic(bundle)
        insight.status = "fallback"
        insight.fallback_reason = reason
        return insight

    async def generate(self, incident: Incident) -> Insight:
        """Run the model if configured. Only a validated model insight is stored."""
        iid = incident.id
        assert iid is not None
        if not self.settings.ai_enabled:
            return self._fallback(await self.bundle_for(incident), "ai_disabled")
        if self.provider is None:
            return self._fallback(await self.bundle_for(incident), "provider_not_configured")
        now = time.monotonic()
        if now - self._last_run.get(iid, -1e9) < MIN_SECONDS_BETWEEN_RUNS:
            raise TooSoon()
        async with self._lock:  # one model call at a time on a laptop
            self._last_run[iid] = time.monotonic()
            if len(self._last_run) > 1000:
                self._last_run.clear()
            max_chars = int(self.settings.ai_max_prompt_chars)
            base_hash = (await self.bundle_for(incident)).hash  # identifies the evidence state, whatever fits the prompt
            bundle: Optional[Bundle] = None
            for evidence_limit in (15, 8, 3, 0):  # shrink evidence until the prompt fits
                bundle = await self.bundle_for(incident, max_evidence=evidence_limit)
                system, user = build_prompt(bundle)
                if len(system) + len(user) <= max_chars:
                    break
            else:
                return self._fallback(bundle, "prompt_too_large")  # type: ignore[arg-type]
            assert bundle is not None
            try:
                bundle.verify_clean(system + user)
            except SanitizationError:
                logger.warning("ai: prompt refused by sanitiser for incident %s", iid)
                return self._fallback(bundle, "sanitization_failed")
            try:
                raw = await self.provider.generate(system, user)
            except ProviderError as exc:
                logger.warning("ai: provider %s for incident %s", exc.code, iid)
                return self._fallback(bundle, "provider_unavailable" if exc.code == "unavailable" else "provider_error")
            except Exception as exc:  # never let a model problem break the API
                logger.warning("ai: unexpected provider failure (%s)", type(exc).__name__)
                return self._fallback(bundle, "provider_error")
            result = validate_model_output(raw, bundle, model=self.provider.model,
                                           max_chars=int(self.settings.ai_max_response_chars))
            if result.insight is None:
                logger.warning("ai: model answer rejected for incident %s (%s)", iid, result.reason)
                return self._fallback(bundle, "invalid_response")
            result.insight.bundle_hash = base_hash
            await self.store.save_ai_insight(result.insight)
            return result.insight
