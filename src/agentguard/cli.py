"""Command-line interface: `agentguard <command>`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from agentguard import __version__
from agentguard.audit import AuditLog, verify_file
from agentguard.guard import Guard
from agentguard.models import Decision, Verdict
from agentguard.policy import load_policy, packaged_policies
from agentguard.risk import risk_level
from agentguard.scenarios import list_scenarios, load_scenario, meets_expectations, run_scenario

_ICON = {
    Verdict.ALLOW: "ALLOW   ",
    Verdict.REDACT: "REDACT  ",
    Verdict.REQUIRE_APPROVAL: "APPROVAL",
    Verdict.DENY: "DENY    ",
}


def _audit_key() -> bytes | None:
    key = os.environ.get("AGENTGUARD_AUDIT_KEY", "")
    return key.encode() if key else None


def _policy_ref(arg: str | None) -> str:
    return arg or os.environ.get("AGENTGUARD_POLICY") or "default"


def _print_decision(d: Decision, as_json: bool) -> None:
    if as_json:
        print(d.model_dump_json(indent=2))
        return
    print(f"verdict: {d.verdict.value}  risk: {d.risk_score} ({risk_level(d.risk_score)})")
    if d.rule:
        print(f"rule:    {d.rule}")
    for r in d.reasons:
        print(f"  - {r}")
    for f in d.findings:
        print(f"  [{f.severity.value}] {f.source}/{f.code}: {f.message}")
    if d.redacted_text is not None:
        print(f"redacted: {d.redacted_text}")
    if d.redacted_arguments is not None:
        print(f"redacted arguments: {json.dumps(d.redacted_arguments)}")


def _exit_for(d: Decision) -> int:
    return {Verdict.DENY: 2, Verdict.REQUIRE_APPROVAL: 3}.get(d.verdict, 0)


def cmd_scan(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.text == "-" else args.text
    guard = Guard(load_policy(_policy_ref(args.policy)))
    d = guard.check_output(text) if args.output else guard.check_input(text)
    _print_decision(d, args.json)
    return _exit_for(d)


def cmd_check_tool(args: argparse.Namespace) -> int:
    try:
        arguments: Any = json.loads(args.args)
    except json.JSONDecodeError as exc:
        print(f"error: --args is not valid JSON: {exc}", file=sys.stderr)
        return 1
    guard = Guard(load_policy(_policy_ref(args.policy)))
    try:
        d = guard.check_tool_call(
            {"tool": args.tool, "arguments": arguments, "agent": args.agent, "cost": args.cost}
        )
    except ValidationError as exc:
        print(f"error: invalid tool call: {exc.errors()[0]['msg']}", file=sys.stderr)
        return 1
    _print_decision(d, args.json)
    return _exit_for(d)


def cmd_demo(args: argparse.Namespace) -> int:
    scenarios = list_scenarios() if args.scenario == "all" else [load_scenario(args.scenario)]
    audit = AuditLog(args.audit, key=_audit_key()) if args.audit else AuditLog(key=_audit_key())
    failed = 0
    report: list[dict[str, Any]] = []
    for sc in scenarios:
        result, _ = run_scenario(sc, audit=audit)
        ok = meets_expectations(sc, result)
        failed += not ok
        if args.json:
            report.append({"scenario": sc.id, "ok": ok, **result.model_dump(mode="json")})
            continue
        print(f"\n=== {sc.id}: {sc.title} (policy: {sc.policy})")
        for st in result.steps:
            if st.decision is None:
                print(f"  {'INVALID ':8}  {st.detail}")
                continue
            label = st.kind if st.kind != "tool_call" else f"tool {st.tool}"
            detail = st.detail.strip().replace("\n", " ")
            if st.kind == "tool_call":
                detail = json.dumps(st.arguments)
            print(
                f"  {_ICON[st.decision.verdict]}  risk {st.decision.risk_score:>3}  {label}: "
                f"{detail[:90]}"
            )
            if st.decision.verdict is not Verdict.ALLOW:
                print(f"            -> {'; '.join(st.decision.reasons)[:140]}")
        print(f"  final: {result.final}")
        print(
            f"  blocked={result.blocked} approvals={result.approvals} "
            f"executed={result.executed}  expectations: {'PASS' if ok else 'FAIL'}"
        )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        chain = audit.verify()
        print(
            f"\naudit: {chain.records} records, chain {'intact' if chain.ok else 'BROKEN'}"
            f", head {audit.head[:16]}"
        )
    return 1 if failed else 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    res = verify_file(args.path, key=_audit_key())
    if res.ok:
        print(f"OK: {res.records} records, hash chain intact")
        return 0
    print(f"TAMPERED: {res.error}", file=sys.stderr)
    return 2


def cmd_policies(args: argparse.Namespace) -> int:
    if args.validate:
        try:
            p = load_policy(args.validate)
        except (OSError, ValueError) as exc:
            print(f"invalid policy: {exc}", file=sys.stderr)
            return 1
        print(f"OK: policy '{p.name}' with {len(p.tools)} tool rules")
        return 0
    for name in packaged_policies():
        p = load_policy(name)
        print(f"{name:10} {len(p.tools):>2} rules  default={p.default_action}  {p.description}")
    return 0


def cmd_scenarios(_: argparse.Namespace) -> int:
    for s in list_scenarios():
        print(f"{s.id:20} policy={s.policy:8} {s.title}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import dataclasses

    import uvicorn

    from agentguard.api import create_app
    from agentguard.api.settings import ApiSettings

    try:
        port = args.port or int(os.getenv("PORT") or 8000)
        settings = ApiSettings.from_env()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.dev:
        settings = dataclasses.replace(settings, dev_mode=True)
    if settings.access_mode == "dev" and args.host not in {"127.0.0.1", "::1", "localhost"}:
        print("warning: dev mode without API keys is exposed beyond localhost", file=sys.stderr)
    mode = {
        "api-key": "API-key auth",
        "dev": "dev mode (no auth)",
        "public-demo": "public demo (packaged policies + mock provider)",
    }[settings.access_mode]
    print(f"AgentGuard {__version__} on http://{args.host}:{port} | {mode}", flush=True)
    uvicorn.run(create_app(settings), host=args.host, port=port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="agentguard", description="Security and governance guardrails for LLM agents."
    )
    ap.add_argument("--version", action="version", version=f"agentguard {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a prompt (or model output) for attacks and PII")
    s.add_argument("text", help="text to scan, or - for stdin")
    s.add_argument("--output", action="store_true", help="treat the text as model output")
    s.add_argument("--policy")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    t = sub.add_parser("check-tool", help="evaluate a proposed tool call against a policy")
    t.add_argument("tool")
    t.add_argument("--args", default="{}", help="tool arguments as JSON")
    t.add_argument("--agent", default="cli")
    t.add_argument("--cost", type=float, default=0.0)
    t.add_argument("--policy")
    t.add_argument("--json", action="store_true")
    t.set_defaults(func=cmd_check_tool)

    d = sub.add_parser("demo", help="run a guarded agent scenario (or 'all')")
    d.add_argument("scenario", nargs="?", default="all")
    d.add_argument("--audit", help="append the audit trail to this JSONL file")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_demo)

    sub.add_parser("scenarios", help="list demo scenarios").set_defaults(func=cmd_scenarios)

    p = sub.add_parser("policies", help="list packaged policies or validate a policy file")
    p.add_argument("--validate", metavar="FILE")
    p.set_defaults(func=cmd_policies)

    a = sub.add_parser("audit", help="audit log tools")
    asub = a.add_subparsers(dest="audit_command", required=True)
    v = asub.add_parser("verify", help="verify the hash chain of an audit log")
    v.add_argument("path")
    v.set_defaults(func=cmd_audit_verify)

    sv = sub.add_parser("serve", help="start the REST API and web dashboard")
    sv.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    sv.add_argument("--port", type=int, default=None, help="port (default: $PORT or 8000)")
    sv.add_argument("--dev", action="store_true", help="dev mode: no API key required")
    sv.set_defaults(func=cmd_serve)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
