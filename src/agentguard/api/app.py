"""FastAPI application: guard endpoints, approvals inbox, audit log and the static dashboard."""

from __future__ import annotations

import hashlib
import math
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi import status as http
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from agentguard import __version__
from agentguard.api.middleware import BodyLimitMiddleware, SecurityHeadersMiddleware
from agentguard.api.schemas import (
    ApprovalListOut,
    AuditOut,
    ConfigOut,
    DecisionOut,
    HealthOut,
    PolicyListOut,
    PolicyRef,
    PolicySummary,
    ResolveIn,
    ScanIn,
    ScenarioListOut,
    ScenarioRunOut,
    ScenarioSummary,
    TextIn,
    ToolCallIn,
    VerifyOut,
)
from agentguard.api.security import ApiKeyAuth, RateLimiter
from agentguard.api.settings import ApiSettings
from agentguard.audit import AuditLog
from agentguard.guard import Approval, Guard
from agentguard.models import Decision, Verdict
from agentguard.policy import Policy, load_policy, packaged_policies
from agentguard.providers import MockProvider, Provider, provider_from_env
from agentguard.scenarios import list_scenarios, load_scenario, meets_expectations, run_scenario

STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY_BYTES = 64 * 1024
MAX_AUDIT_VIEW = 200
IdParam = Annotated[str, PathParam(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]


@dataclass(frozen=True)
class Caller:
    """``owner`` tags approvals a caller created, ``client`` keys rate limits and ``trusted``
    unlocks inline policies, real providers and resolving anyone's approvals."""

    owner: str
    client: str
    trusted: bool


def client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        # The right-most hop is the one appended by the trusted edge proxy; anything to its
        # left is client-supplied and can be forged.
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",")]
        hops = [h for h in hops if h]
        if hops:
            return hops[-1][:64]
    return request.client.host if request.client else "unknown"


def presented_key(request: Request) -> str | None:
    key = request.headers.get("x-api-key")
    if key and key.strip():
        return key.strip()
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


def _retry_after(seconds: float) -> dict[str, str]:
    return {"Retry-After": str(max(1, math.ceil(seconds)))}


@dataclass(frozen=True)
class AccessGuard:
    """Authenticates a request and applies the general per-caller rate limit."""

    settings: ApiSettings
    auth: ApiKeyAuth
    limiter: RateLimiter

    def identify(self, request: Request) -> Caller | None:
        if self.auth.enabled:
            fp = self.auth.verify(presented_key(request))
            return Caller(f"key:{fp}", f"key:{fp}", True) if fp else None
        ip = client_ip(request, self.settings.trust_proxy)
        if self.settings.dev_mode:
            return Caller("dev", f"ip:{ip}", True)
        anon = "anon:" + hashlib.sha256(ip.encode()).hexdigest()[:12]
        return Caller(anon, f"ip:{ip}", False)

    def __call__(self, request: Request) -> Caller:
        who = self.identify(request)
        if who is None:
            raise HTTPException(
                http.HTTP_401_UNAUTHORIZED,
                "Missing or invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        retry = self.limiter.check(who.client)
        if retry is not None:
            raise HTTPException(
                http.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded", headers=_retry_after(retry)
            )
        return who


def get_caller(request: Request) -> Caller:
    access: AccessGuard = request.app.state.access
    return access(request)


CallerDep = Annotated[Caller, Depends(get_caller)]


class GuardRegistry:
    """One long-lived :class:`Guard` per packaged policy (so rate limits and budgets persist),
    all writing to one shared audit chain; approvals are indexed with their creator."""

    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit
        self._guards: dict[str, Guard] = {}
        self._approvals: dict[str, tuple[Guard, str]] = {}
        self._lock = threading.Lock()

    def packaged(self, name: str) -> Guard:
        with self._lock:
            guard = self._guards.get(name)
            if guard is None:
                guard = self._guards[name] = Guard(load_policy(name), audit=self.audit)
            return guard

    def track(self, guard: Guard, decision: Decision, owner: str) -> str | None:
        if decision.verdict is not Verdict.REQUIRE_APPROVAL:
            return None
        for a in guard.approvals("pending"):
            if a.decision is decision:
                with self._lock:
                    self._approvals[a.id] = (guard, owner)
                return a.id
        return None

    def lookup(self, approval_id: str) -> tuple[Guard, str] | None:
        with self._lock:
            return self._approvals.get(approval_id)

    def list(self, owner: str | None, status: str | None) -> list[Approval]:
        with self._lock:
            entries = list(self._approvals.items())
        out: list[Approval] = []
        for aid, (guard, who) in entries:
            if owner is not None and who != owner:
                continue
            out += [a for a in guard.approvals(status) if a.id == aid]
        return list(reversed(out))


def create_app(settings: ApiSettings | None = None) -> FastAPI:
    cfg = settings or ApiSettings.from_env()
    audit = AuditLog(cfg.audit_path, key=cfg.audit_key)
    registry = GuardRegistry(audit)
    policy_names = packaged_policies()
    scenario_list = list_scenarios()
    scenario_ids = [s.id for s in scenario_list]
    scenario_limiter = RateLimiter(cfg.scenario_limit_per_minute)
    configured_provider = (
        "mock" if cfg.public_demo else os.getenv("AGENTGUARD_PROVIDER", "mock").strip() or "mock"
    )

    app = FastAPI(
        title="AgentGuard API",
        version=__version__,
        description=(
            "AI agent security & governance: screen prompts, model outputs and proposed tool "
            "calls against declarative policies, queue risky actions for human approval and "
            "keep a tamper-evident audit trail."
        ),
    )
    app.state.access = AccessGuard(
        cfg, ApiKeyAuth(cfg.api_keys), RateLimiter(cfg.rate_limit_per_minute)
    )
    app.state.registry = registry

    if cfg.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cfg.cors_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-API-Key", "Authorization"],
            allow_credentials=False,
            max_age=600,
        )
    app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_BODY_BYTES)
    app.add_middleware(SecurityHeadersMiddleware)

    def resolve_guard(ref: PolicyRef, who: Caller) -> tuple[Guard, str]:
        if ref.policy is not None and ref.custom_policy is not None:
            raise HTTPException(
                http.HTTP_422_UNPROCESSABLE_CONTENT, "Provide policy or custom_policy, not both"
            )
        if ref.custom_policy is not None:
            if not who.trusted:
                raise HTTPException(
                    http.HTTP_403_FORBIDDEN,
                    "Public demo: only packaged policies are enabled (custom ones need an API key)",
                )
            return Guard(ref.custom_policy, audit=audit), ref.custom_policy.name
        name = ref.policy or "default"
        if name not in policy_names:
            raise HTTPException(http.HTTP_422_UNPROCESSABLE_CONTENT, f"unknown policy {name!r}")
        return registry.packaged(name), name

    # ------------------------------------------------------------------ meta
    @app.get("/healthz", response_model=HealthOut, tags=["meta"])
    def healthz() -> HealthOut:
        return HealthOut(version=__version__)

    @app.get("/api/config", response_model=ConfigOut, tags=["meta"])
    def config(request: Request) -> ConfigOut:
        access: AccessGuard = request.app.state.access
        who = access.identify(request)
        return ConfigOut(
            version=__version__,
            access_mode=cfg.access_mode,
            auth_required=cfg.auth_enabled,
            authenticated=who is not None and cfg.auth_enabled,
            custom_policies_allowed=not cfg.public_demo,
            provider=configured_provider,
            policies=policy_names,
            scenarios=scenario_ids,
            audit_signed=cfg.audit_key is not None,
            audit_persistent=cfg.audit_path is not None,
        )

    # ----------------------------------------------------------------- guard
    def _decide(guard: Guard, name: str, d: Decision, who: Caller) -> DecisionOut:
        return DecisionOut(decision=d, policy=name, approval_id=registry.track(guard, d, who.owner))

    @app.post("/api/guard/input", response_model=DecisionOut, tags=["guard"])
    def guard_input(body: TextIn, who: CallerDep) -> DecisionOut:
        guard, name = resolve_guard(body, who)
        return _decide(guard, name, guard.check_input(body.text, agent=body.agent), who)

    @app.post("/api/guard/output", response_model=DecisionOut, tags=["guard"])
    def guard_output(body: TextIn, who: CallerDep) -> DecisionOut:
        guard, name = resolve_guard(body, who)
        return _decide(guard, name, guard.check_output(body.text, agent=body.agent), who)

    @app.post("/api/guard/tool-call", response_model=DecisionOut, tags=["guard"])
    def guard_tool_call(body: ToolCallIn, who: CallerDep) -> DecisionOut:
        guard, name = resolve_guard(body, who)
        return _decide(guard, name, guard.check_tool_call(body.call), who)

    @app.post("/api/scan", response_model=DecisionOut, tags=["guard"])
    def scan(body: ScanIn, who: CallerDep) -> DecisionOut:
        guard, name = resolve_guard(body, who)
        check = guard.check_output if body.mode == "output" else guard.check_input
        return _decide(guard, name, check(body.text, agent="scan"), who)

    # ------------------------------------------------------------- approvals
    @app.get("/api/approvals", response_model=ApprovalListOut, tags=["approvals"])
    def approvals(
        who: CallerDep,
        status: Annotated[str | None, Query(pattern="^(pending|approved|rejected)$")] = None,
    ) -> ApprovalListOut:
        owner = None if who.trusted else who.owner
        return ApprovalListOut(approvals=registry.list(owner, status)[:100])

    def _resolve(approval_id: str, body: ResolveIn, who: Caller, approved: bool) -> Approval:
        entry = registry.lookup(approval_id)
        if entry is None or (not who.trusted and entry[1] != who.owner):
            raise HTTPException(http.HTTP_404_NOT_FOUND, "Approval not found")
        try:
            return entry[0].resolve(
                approval_id, approved=approved, reviewer=body.reviewer, note=body.note
            )
        except ValueError as exc:
            raise HTTPException(http.HTTP_409_CONFLICT, str(exc)) from exc

    @app.post("/api/approvals/{approval_id}/approve", response_model=Approval, tags=["approvals"])
    def approve(approval_id: IdParam, who: CallerDep, body: ResolveIn | None = None) -> Approval:
        return _resolve(approval_id, body or ResolveIn(), who, True)

    @app.post("/api/approvals/{approval_id}/deny", response_model=Approval, tags=["approvals"])
    def deny(approval_id: IdParam, who: CallerDep, body: ResolveIn | None = None) -> Approval:
        return _resolve(approval_id, body or ResolveIn(), who, False)

    # ----------------------------------------------------------------- audit
    @app.get("/api/audit", response_model=AuditOut, tags=["audit"])
    def audit_view(
        _: CallerDep, limit: Annotated[int, Query(ge=1, le=MAX_AUDIT_VIEW)] = 50
    ) -> AuditOut:
        records = audit.records
        return AuditOut(total=len(records), head=audit.head, records=records[-limit:][::-1])

    @app.get("/api/audit/verify", response_model=VerifyOut, tags=["audit"])
    def audit_verify(_: CallerDep) -> VerifyOut:
        res = audit.verify()
        return VerifyOut(
            ok=res.ok,
            records=res.records,
            error=res.error,
            bad_index=res.bad_index,
            head=audit.head,
        )

    # -------------------------------------------------------------- policies
    def _summary(p: Policy) -> PolicySummary:
        return PolicySummary(
            name=p.name,
            description=p.description,
            default_action=p.default_action,
            rules=len(p.tools),
        )

    @app.get("/api/policies", response_model=PolicyListOut, tags=["policies"])
    def policies(_: CallerDep) -> PolicyListOut:
        return PolicyListOut(policies=[_summary(load_policy(n)) for n in policy_names])

    @app.get("/api/policies/{name}", response_model=Policy, tags=["policies"])
    def policy_detail(name: IdParam, _: CallerDep) -> Policy:
        if name not in policy_names:
            raise HTTPException(http.HTTP_404_NOT_FOUND, "Policy not found")
        return load_policy(name)

    # ------------------------------------------------------------- scenarios
    @app.get("/api/scenarios", response_model=ScenarioListOut, tags=["scenarios"])
    def scenarios(_: CallerDep) -> ScenarioListOut:
        return ScenarioListOut(
            scenarios=[
                ScenarioSummary(
                    id=s.id,
                    title=s.title,
                    description=s.description,
                    policy=s.policy,
                    expect=s.expect.model_dump(),
                )
                for s in scenario_list
            ]
        )

    @app.post("/api/scenarios/{scenario_id}/run", response_model=ScenarioRunOut, tags=["scenarios"])
    def scenario_run(scenario_id: IdParam, who: CallerDep) -> ScenarioRunOut:
        if scenario_id not in scenario_ids:
            raise HTTPException(http.HTTP_404_NOT_FOUND, "Scenario not found")
        retry = scenario_limiter.check(who.client)
        if retry is not None:
            raise HTTPException(
                http.HTTP_429_TOO_MANY_REQUESTS,
                "Scenario rate limit exceeded",
                headers=_retry_after(retry),
            )
        sc = load_scenario(scenario_id)
        provider: Provider = (
            MockProvider(sc.script) if cfg.public_demo else provider_from_env(sc.script)
        )
        try:
            result, _guard = run_scenario(sc, audit=audit, provider=provider)
        except Exception as exc:  # a failing LLM backend must not leak internals
            raise HTTPException(
                http.HTTP_502_BAD_GATEWAY, f"scenario failed: {type(exc).__name__}"
            ) from exc
        return ScenarioRunOut(
            scenario=sc.id,
            policy=sc.policy,
            provider=configured_provider,
            meets_expectations=meets_expectations(sc, result),
            steps=result.steps,
            final=result.final,
            blocked=result.blocked,
            approvals=result.approvals,
            executed=result.executed,
            audit_head=audit.head,
        )

    # ------------------------------------------------------------- dashboard
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
