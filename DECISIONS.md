# Decisions

The default is a dry run, and the result exposes the canonical SHA-256 payload
hash so a reviewer can inspect exactly what would be written. Live execution
requires an HMAC-backed approval artifact whose hash and nonce match the
payload; the nonce is consumed before the synthetic write. A process-local lock
protects the idempotency check and write in this assessment. Production code
would replace that lock and in-memory state with a transactional durable store
or an atomic uniqueness constraint.

The audit file is append-only JSONL and records event type, idempotency key,
payload hash, and record id only. It intentionally omits raw payloads and
secrets. The supplied client is synthetic and no external service or credential
is used.

## Incident note

The original shape of this workflow could perform an external write while a
caller believed it was in preview mode, repeat the same write after a retry or
concurrent request, and leave no reliable explanation of what happened. A
payload hash bound to a one-time approval, a durable idempotency record, and
sanitized audit events close those failure paths.

## AI disclosure and verification

AI assistance was used to draft this small example. The implementation was
reviewed manually, and `python -m pytest -q` verifies dry-run blocking, exact
approval binding, retry/concurrency idempotency, and absence of raw payloads in
the audit trail.
