# Fail-closed Python workflow assessment

This is a small synthetic implementation for the Freelancer technical assessment. It keeps dry-run as the default, binds a one-time HMAC approval to the exact canonical payload hash, protects the idempotency check/write with a lock, and appends sanitized JSONL audit events.

Run the tests with:

```powershell
python -m unittest -v
```

No external services, credentials, or real records are used.
