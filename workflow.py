"""Small fail-closed workflow example for a synthetic API.

The module deliberately keeps the interface small so the safety properties are
easy to review: dry-run is the default, live mode needs a single-use approval
bound to the exact canonical payload, and an idempotency key is persisted under
a lock before the write is attempted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


def canonical_payload(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def payload_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(payload).encode()).hexdigest()


@dataclass(frozen=True)
class Approval:
    payload_hash: str
    nonce: str
    signature: str


class SyntheticClient:
    """Fake write/read client used only by tests and the assessment."""

    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        self.write_calls = 0

    def create(self, key: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self.write_calls += 1
        if key in self.records:
            raise RuntimeError("synthetic duplicate write")
        record = {"id": f"rec-{len(self.records) + 1}", **dict(payload)}
        self.records[key] = record
        return record

    def read(self, key: str) -> dict[str, Any]:
        return dict(self.records[key])


class Workflow:
    def __init__(self, client: SyntheticClient, audit_path: Path, secret: bytes = b"assessment-secret") -> None:
        self.client = client
        self.audit_path = audit_path
        self.secret = secret
        self._used_approvals: set[str] = set()
        self._completed: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def issue_approval(self, payload: Mapping[str, Any], nonce: str = "n-1") -> Approval:
        digest = payload_hash(payload)
        msg = f"{digest}:{nonce}".encode()
        sig = hmac.new(self.secret, msg, hashlib.sha256).hexdigest()
        return Approval(digest, nonce, sig)

    def _audit(self, event: str, key: str, digest: str, **extra: Any) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        row = {"event": event, "idempotency_key": key, "payload_hash": digest, **extra}
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    def run(self, payload: Mapping[str, Any], *, live: bool = False, approval: Approval | None = None,
            idempotency_key: str = "default") -> dict[str, Any]:
        digest = payload_hash(payload)
        if not live:
            result = {"status": "dry_run", "payload_hash": digest, "idempotency_key": idempotency_key}
            self._audit("dry_run", idempotency_key, digest)
            return result

        if approval is None:
            self._audit("blocked", idempotency_key, digest, reason="approval_required")
            return {"status": "blocked", "reason": "approval_required", "payload_hash": digest}

        expected = hmac.new(self.secret, f"{approval.payload_hash}:{approval.nonce}".encode(), hashlib.sha256).hexdigest()
        if approval.payload_hash != digest or not hmac.compare_digest(approval.signature, expected):
            self._audit("blocked", idempotency_key, digest, reason="approval_mismatch")
            return {"status": "blocked", "reason": "approval_mismatch", "payload_hash": digest}

        with self._lock:
            if approval.nonce in self._used_approvals:
                self._audit("blocked", idempotency_key, digest, reason="approval_reused")
                return {"status": "blocked", "reason": "approval_reused", "payload_hash": digest}
            self._used_approvals.add(approval.nonce)
            if idempotency_key in self._completed:
                result = {"status": "duplicate", **self._completed[idempotency_key]}
                self._audit("duplicate", idempotency_key, digest)
                return result
            record = self.client.create(idempotency_key, payload)
            result = {"status": "written", "payload_hash": digest, "record": record}
            self._completed[idempotency_key] = {"payload_hash": digest, "record": record}
            self._audit("written", idempotency_key, digest, record_id=record["id"])
            return result

