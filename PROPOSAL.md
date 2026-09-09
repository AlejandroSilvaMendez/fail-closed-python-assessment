# Proposal draft

1. In the attached Python workflow, the risky path was an external create that could run from a preview call or repeat after a retry. I made dry-run the default, require an approval bound to the exact payload hash, reserve the idempotency key under a lock, and return a machine-readable duplicate result. The test suite covers tampering, replay, retries, and concurrent threads; the public JHipster Playwright contribution shows the same review-and-test discipline.

2. I canonicalize the payload with sorted JSON and hash it with SHA-256. The approval carries that digest, a nonce, and an HMAC signature. Live mode verifies the signature and exact digest, consumes the nonce once, and never logs the secret or raw payload.

3. I test a normal retry with the same idempotency key and several concurrent attempts with the same key. The fake client counts writes, so the invariant is one write and one `duplicate` result for every later attempt. In production I would back the reservation with a transactional database uniqueness constraint shared by all workers.

4. I confirm that I am an individual professional and the sole author of the submitted work. I will disclose AI tools used for drafting or analysis and manually verify the resulting code and tests.

5. I can respect the four-hour timebox. I will run the documented test command, deliver the patch and notes, and record any unfinished item rather than extending the assessment.
