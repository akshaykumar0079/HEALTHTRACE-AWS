"""Optional local model access. Off unless explicitly configured.

Only Ollama's HTTP API on the loopback interface is supported: the URL host must
be 127.0.0.1, localhost or ::1, redirects are not followed, system proxies are not
used, the response size is capped and every call has a timeout. Nothing leaves the
machine, and no credentials are involved.
"""

from __future__ import annotations

import asyncio
import http.client
import json
from typing import Any, Optional, Protocol
from urllib.parse import urlparse

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class ProviderError(RuntimeError):
    """``code`` is 'unavailable' (cannot connect/timeout) or 'error' (bad status/body)."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


class Provider(Protocol):
    name: str
    model: str

    async def generate(self, system: str, prompt: str) -> str: ...


def parse_loopback_url(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme != "http" or host not in _LOOPBACK:
        raise ValueError("AI_OLLAMA_URL must be http://127.0.0.1, http://localhost or http://[::1] (local only)")
    if parsed.username or parsed.password:
        raise ValueError("AI_OLLAMA_URL must not contain credentials")
    return host, parsed.port or 11434


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, model: str, *, timeout: float = 30.0, max_response_bytes: int = 64_000) -> None:
        self.host, self.port = parse_loopback_url(base_url)
        self.model = model
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def _call(self, system: str, prompt: str) -> str:
        body = json.dumps({
            "model": self.model, "system": system, "prompt": prompt, "stream": False, "format": "json",
            "options": {"temperature": 0, "num_predict": 1200},
        }).encode()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request("POST", "/api/generate", body=body, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read(self.max_response_bytes + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise ProviderError("unavailable", type(exc).__name__) from None
        finally:
            conn.close()
        if resp.status != 200:
            raise ProviderError("error", f"HTTP {resp.status}")
        if len(data) > self.max_response_bytes:
            raise ProviderError("error", "response too large")
        try:
            payload = json.loads(data)
            text = payload["response"]
        except (ValueError, KeyError, TypeError):
            raise ProviderError("error", "unexpected response shape") from None
        if not isinstance(text, str):
            raise ProviderError("error", "unexpected response shape")
        return text

    async def generate(self, system: str, prompt: str) -> str:
        try:
            return await asyncio.wait_for(asyncio.to_thread(self._call, system, prompt), self.timeout + 2)
        except asyncio.TimeoutError:
            raise ProviderError("unavailable", "timeout") from None


def build_provider(settings: Any) -> Optional[Provider]:
    """None unless AI is enabled, a provider is chosen and a model name is set."""
    if not getattr(settings, "ai_enabled", False) or getattr(settings, "ai_provider", "none") != "ollama":
        return None
    if not str(settings.ai_model).strip():
        return None
    return OllamaProvider(settings.ai_ollama_url, settings.ai_model.strip(), timeout=float(settings.ai_timeout_seconds))
