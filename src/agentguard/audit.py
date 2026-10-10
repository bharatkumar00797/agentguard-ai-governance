"""Tamper-evident audit log.

Every record stores the SHA-256 of the previous record, and its own hash covers its content
plus that link (a hash chain, like a minimal blockchain without consensus). Editing, deleting
or reordering any past record breaks verification from that point on. With an optional HMAC
key the hashes also cannot be recomputed by someone who can write the file but lacks the key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    error: str | None = None
    bad_index: int | None = None


class AuditLog:
    def __init__(self, path: str | Path | None = None, *, key: bytes | None = None) -> None:
        self.path = Path(path) if path else None
        self._key = key
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        if self.path and self.path.exists():
            self._records = _read(self.path)

    def _digest(self, body: dict[str, Any]) -> str:
        data = _canonical(body)
        if self._key:
            return hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    @property
    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)

    @property
    def head(self) -> str:
        with self._lock:
            return self._records[-1]["hash"] if self._records else GENESIS

    def append(self, event: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            prev = self._records[-1]["hash"] if self._records else GENESIS
            body: dict[str, Any] = {
                "index": len(self._records),
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "event": event,
                "data": json.loads(json.dumps(data, default=str)),
                "prev_hash": prev,
            }
            record = {**body, "hash": self._digest(body)}
            self._records.append(record)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, sort_keys=True) + "\n")
            return record

    def verify(self) -> VerifyResult:
        return verify_records(self.records, key=self._key)


def _read(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def verify_records(records: list[dict[str, Any]], *, key: bytes | None = None) -> VerifyResult:
    prev = GENESIS
    for i, rec in enumerate(records):
        if rec.get("index") != i:
            return VerifyResult(False, len(records), f"record {i} has index {rec.get('index')}", i)
        if rec.get("prev_hash") != prev:
            return VerifyResult(False, len(records), f"record {i} breaks the hash chain", i)
        body = {k: v for k, v in rec.items() if k != "hash"}
        data = _canonical(body)
        expected = (
            hmac.new(key, data, hashlib.sha256).hexdigest()
            if key
            else hashlib.sha256(data).hexdigest()
        )
        if not hmac.compare_digest(expected, str(rec.get("hash", ""))):
            return VerifyResult(False, len(records), f"record {i} content was modified", i)
        prev = rec["hash"]
    return VerifyResult(True, len(records))


def verify_file(path: str | Path, *, key: bytes | None = None) -> VerifyResult:
    try:
        records = _read(Path(path))
    except (OSError, json.JSONDecodeError) as exc:
        return VerifyResult(False, 0, f"cannot read audit log: {exc}")
    return verify_records(records, key=key)
