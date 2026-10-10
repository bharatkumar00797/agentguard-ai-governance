"""LLM providers. The mock provider is offline and deterministic; the OpenAI-compatible
provider works with OpenAI, Groq, Ollama and any server speaking /chat/completions."""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from typing import Protocol

import httpx

Message = dict[str, str]


class Provider(Protocol):
    name: str

    def complete(self, messages: Sequence[Message]) -> str: ...


class MockProvider:
    """Replays a scripted list of agent replies (one per call), then finishes.

    This stands in for a model that may be compromised by injected content, so the guard's
    behaviour can be demonstrated and tested without any network access.
    """

    name = "mock"

    def __init__(self, script: Sequence[str] | None = None) -> None:
        self._script = list(script or [])
        self._i = 0

    def complete(self, messages: Sequence[Message]) -> str:
        if self._i < len(self._script):
            reply = self._script[self._i]
            self._i += 1
            return reply
        return '{"final": "Task complete."}'


class OpenAICompatibleProvider:
    name = "openai"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        timeout: float = 30.0,
        retries: int = 2,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.retries = retries
        self._client = client or httpx.Client(timeout=timeout)
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    def complete(self, messages: Sequence[Message]) -> str:
        payload = {"model": self.model, "messages": list(messages), "temperature": 0}
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                r = self._client.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=self._headers
                )
                if r.status_code in (429, 500, 502, 503, 504):
                    raise httpx.HTTPStatusError("retryable", request=r.request, response=r)
                r.raise_for_status()
                content = r.json()["choices"][0]["message"]["content"]
                return str(content or "")
            except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                last = exc
                if attempt < self.retries:
                    time.sleep(0.5 * 2**attempt)
        raise RuntimeError(f"LLM request failed: {type(last).__name__}") from last


_DEFAULT_URLS = {
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "ollama": "http://localhost:11434/v1",
}


def provider_from_env(script: Sequence[str] | None = None) -> Provider:
    kind = os.environ.get("AGENTGUARD_PROVIDER", "mock").strip().lower() or "mock"
    if kind == "mock":
        return MockProvider(script)
    if kind not in _DEFAULT_URLS:
        raise ValueError(f"unknown provider '{kind}' (use mock, openai, groq or ollama)")
    return OpenAICompatibleProvider(
        os.environ.get("AGENTGUARD_BASE_URL") or _DEFAULT_URLS[kind],
        os.environ.get("AGENTGUARD_API_KEY", ""),
        os.environ.get("AGENTGUARD_MODEL", "gpt-4o-mini"),
    )
