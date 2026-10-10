"""Configuration for the HTTP service, loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

AccessMode = Literal["api-key", "dev", "public-demo"]


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean (true/false), got {raw!r}")


def _env_list(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class ApiSettings:
    """Service settings.

    Access modes:

    * keys configured (``AGENTGUARD_API_KEYS``) -> every ``/api`` call needs ``X-API-Key`` or a
      Bearer token; callers may send inline custom policies, run scenarios with the configured
      LLM provider and resolve any pending approval.
    * ``dev_mode`` -> no auth and full access; meant for ``localhost`` only.
    * neither -> public demo: anonymous callers may only use packaged policies and scenarios with
      the offline mock provider, and only resolve approvals their own requests created.
    """

    api_keys: tuple[str, ...] = ()
    dev_mode: bool = False
    cors_origins: tuple[str, ...] = ()
    rate_limit_per_minute: int = 120
    scenario_limit_per_minute: int = 20
    trust_proxy: bool = False
    audit_path: str | None = None
    audit_key: bytes | None = None

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_keys)

    @property
    def access_mode(self) -> AccessMode:
        if self.auth_enabled:
            return "api-key"
        return "dev" if self.dev_mode else "public-demo"

    @property
    def public_demo(self) -> bool:
        return self.access_mode == "public-demo"

    @classmethod
    def from_env(cls) -> ApiSettings:
        key = os.getenv("AGENTGUARD_AUDIT_KEY", "")
        return cls(
            api_keys=_env_list("AGENTGUARD_API_KEYS"),
            dev_mode=env_bool("AGENTGUARD_DEV_MODE", False),
            cors_origins=_env_list("AGENTGUARD_CORS_ORIGINS"),
            rate_limit_per_minute=env_int("AGENTGUARD_RATE_LIMIT_PER_MINUTE", 120),
            scenario_limit_per_minute=env_int("AGENTGUARD_SCENARIO_LIMIT_PER_MINUTE", 20),
            trust_proxy=env_bool("AGENTGUARD_TRUST_PROXY", False),
            audit_path=os.getenv("AGENTGUARD_SERVER_AUDIT_LOG") or None,
            audit_key=key.encode() if key else None,
        )
