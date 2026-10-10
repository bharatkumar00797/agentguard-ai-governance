import json
from pathlib import Path

from agentguard.audit import GENESIS, AuditLog, verify_file
from agentguard.models import Finding, Severity
from agentguard.risk import risk_level, risk_score


def _log(tmp_path: Path, key: bytes | None = None) -> tuple[AuditLog, Path]:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, key=key)
    for i in range(4):
        log.append("tool_call", {"i": i, "verdict": "allow"})
    return log, path


def test_chain_links_and_verifies(tmp_path: Path) -> None:
    log, path = _log(tmp_path)
    recs = log.records
    assert recs[0]["prev_hash"] == GENESIS
    assert all(recs[i]["prev_hash"] == recs[i - 1]["hash"] for i in range(1, 4))
    assert verify_file(path).ok and log.verify().records == 4


def test_reopen_continues_chain(tmp_path: Path) -> None:
    _, path = _log(tmp_path)
    again = AuditLog(path)
    again.append("x", {})
    res = verify_file(path)
    assert res.ok and res.records == 5


def test_detects_edit_delete_and_reorder(tmp_path: Path) -> None:
    _, path = _log(tmp_path)
    lines = path.read_text().splitlines()

    edited = json.loads(lines[1])
    edited["data"]["verdict"] = "deny"
    path.write_text("\n".join([lines[0], json.dumps(edited), *lines[2:]]))
    res = verify_file(path)
    assert not res.ok and res.bad_index == 1 and "modified" in (res.error or "")

    path.write_text("\n".join([lines[0], *lines[2:]]))
    assert not verify_file(path).ok

    path.write_text("\n".join([lines[1], lines[0], *lines[2:]]))
    assert not verify_file(path).ok


def test_hmac_key_required_to_forge(tmp_path: Path) -> None:
    _, path = _log(tmp_path, key=b"k1")
    assert verify_file(path, key=b"k1").ok
    assert not verify_file(path).ok
    assert not verify_file(path, key=b"other").ok


def test_unreadable_log(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json")
    assert not verify_file(bad).ok


def f(sev: Severity) -> Finding:
    return Finding(source="t", code="c", severity=sev, message="m")


def test_risk_score_monotonic_and_bounded() -> None:
    assert risk_score([]) == 0
    one = risk_score([f(Severity.HIGH)])
    two = risk_score([f(Severity.HIGH), f(Severity.MEDIUM)])
    assert one == 50 and one < two <= 100
    assert risk_score([f(Severity.LOW)] * 20) < risk_score([f(Severity.CRITICAL)])
    assert risk_score([f(Severity.CRITICAL)] * 10) <= 100
    assert [risk_level(s) for s in (0, 30, 70, 90)] == ["low", "medium", "high", "critical"]
