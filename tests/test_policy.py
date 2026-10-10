from pathlib import Path

import pytest
from pydantic import ValidationError

from agentguard.limits import BudgetTracker, RateLimiter
from agentguard.models import ToolCall, Verdict
from agentguard.policy import (
    ArgConstraint,
    Policy,
    PolicyEngine,
    check_argument,
    load_policy,
    packaged_policies,
)


def engine(name: str = "default") -> PolicyEngine:
    return PolicyEngine(load_policy(name))


def call(tool: str, **args: object) -> ToolCall:
    return ToolCall(tool=tool, arguments=dict(args))


def test_packaged_policies_load() -> None:
    assert {"default", "fintech", "devops"} <= set(packaged_policies())


def test_default_deny_for_unknown_tool() -> None:
    r = engine().evaluate(call("launch_missiles"))
    assert r.verdict is Verdict.DENY and r.rule is None


def test_explicit_deny_and_glob() -> None:
    assert engine().evaluate(call("shell", cmd="ls")).verdict is Verdict.DENY
    r = engine().evaluate(call("delete_user", id=1))
    assert r.verdict is Verdict.DENY and r.rule == "deny-delete"


def test_path_prefix_and_traversal() -> None:
    e = engine()
    assert e.evaluate(call("read_file", path="workspace/a.txt")).verdict is Verdict.ALLOW
    assert e.evaluate(call("read_file", path="workspace/../etc/passwd")).verdict is Verdict.DENY
    assert e.evaluate(call("read_file", path="/etc/passwd")).verdict is Verdict.DENY
    assert e.evaluate(call("read_file", path="workspace/.env")).verdict is Verdict.DENY


def test_domain_allowlist() -> None:
    e = engine()
    ok = e.evaluate(call("http_get", url="https://en.wikipedia.org/wiki/AI"))
    assert ok.verdict is Verdict.ALLOW
    bad = e.evaluate(call("http_get", url="https://wikipedia.org.evil.io/x"))
    assert bad.verdict is Verdict.DENY
    userinfo = e.evaluate(call("http_get", url="https://api.github.com@evil.io/"))
    assert userinfo.verdict is Verdict.DENY
    assert e.evaluate(call("http_get", url="http://api.github.com/")).verdict is Verdict.DENY


def test_required_and_extra_args() -> None:
    e = engine()
    r = e.evaluate(call("send_email", to="a@example.com", subject="s"))
    assert r.verdict is Verdict.DENY and "missing required argument 'body'" in r.reasons
    r = e.evaluate(call("send_email", to="a@example.com", subject="s", body="b", bcc="x"))
    assert r.verdict is Verdict.DENY and "unexpected arguments: bcc" in r.reasons


def test_approval_gates() -> None:
    e = engine("fintech")
    small = call("issue_refund", customer_id="CUS-000001", amount=20, currency="USD")
    big = call("issue_refund", customer_id="CUS-000001", amount=700, currency="USD")
    huge = call("issue_refund", customer_id="CUS-000001", amount=7000, currency="USD")
    assert e.evaluate(small).verdict is Verdict.ALLOW
    assert e.evaluate(big).verdict is Verdict.REQUIRE_APPROVAL
    assert e.evaluate(huge).verdict is Verdict.DENY
    assert e.evaluate(call("transfer_funds", amount=5)).verdict is Verdict.REQUIRE_APPROVAL


def test_type_checks_reject_bool_as_number() -> None:
    assert check_argument("x", True, ArgConstraint(type="number"))
    assert not check_argument("x", 3, ArgConstraint(type="number", min=1, max=5))
    assert check_argument("x", "a", ArgConstraint(enum=["b"]))


def test_rate_limit_with_fake_clock() -> None:
    now = [0.0]
    e = PolicyEngine(load_policy("default"), rate_limiter=RateLimiter(clock=lambda: now[0]))
    q = call("web_search", query="x")
    results = [e.evaluate(q).verdict for _ in range(11)]
    assert results[:10] == [Verdict.ALLOW] * 10 and results[10] is Verdict.DENY
    now[0] = 61
    assert e.evaluate(q).verdict is Verdict.ALLOW


def test_rate_limit_is_per_agent() -> None:
    e = engine()
    for _ in range(10):
        e.evaluate(ToolCall(tool="web_search", arguments={"query": "x"}, agent="a"))
    other = ToolCall(tool="web_search", arguments={"query": "x"}, agent="b")
    assert e.evaluate(other).verdict is Verdict.ALLOW


def test_budget() -> None:
    e = PolicyEngine(load_policy("default"), budgets=BudgetTracker())
    c = ToolCall(tool="llm_completion", cost=0.4)
    assert [e.evaluate(c).verdict for _ in range(3)] == [
        Verdict.ALLOW,
        Verdict.ALLOW,
        Verdict.DENY,
    ]


def test_policy_validation_rejects_bad_files(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("name: x\ntools:\n  - name: r\n    tools: [a]\n    action: maybe\n")
    with pytest.raises(ValidationError):
        load_policy(bad)
    bad.write_text("name: x\nunknown_key: 1\n")
    with pytest.raises(ValidationError):
        load_policy(bad)
    with pytest.raises(FileNotFoundError):
        load_policy("../etc/passwd")


def test_json_policy_and_agent_scoping(tmp_path: Path) -> None:
    f = tmp_path / "p.json"
    f.write_text(
        '{"name": "j", "default_action": "allow", "tools": '
        '[{"name": "ops-only", "tools": ["deploy"], "agents": ["ops-*"]}, '
        '{"name": "no-deploy", "tools": ["deploy"], "action": "deny"}]}'
    )
    e = PolicyEngine(load_policy(f))
    assert e.evaluate(ToolCall(tool="deploy", agent="ops-bot")).verdict is Verdict.ALLOW
    assert e.evaluate(ToolCall(tool="deploy", agent="sales")).verdict is Verdict.DENY
    assert e.evaluate(ToolCall(tool="other")).verdict is Verdict.ALLOW


def test_tool_name_validation() -> None:
    with pytest.raises(ValidationError):
        ToolCall(tool="rm -rf /")
    assert Policy(name="p").default_action == "deny"
