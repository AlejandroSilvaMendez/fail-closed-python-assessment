import json
import threading
import unittest
from pathlib import Path

from workflow import SyntheticClient, Workflow


def make(tmp_path: Path):
    client = SyntheticClient()
    return client, Workflow(client, tmp_path / "audit.jsonl")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__import__("tempfile").mkdtemp())

    def test_dry_run_is_default_and_does_not_write(self):
        client, flow = make(self.tmp)
        result = flow.run({"name": "synthetic"})
        self.assertEqual(result["status"], "dry_run")
        self.assertEqual(client.write_calls, 0)


    def test_live_requires_exact_approval_and_is_single_use(self):
        client, flow = make(self.tmp)
        payload = {"name": "synthetic"}
        approval = flow.issue_approval(payload)
        self.assertEqual(flow.run({"name": "tampered"}, live=True, approval=approval)["status"], "blocked")
        self.assertEqual(flow.run(payload, live=True, approval=approval, idempotency_key="k")["status"], "written")
        self.assertEqual(flow.run(payload, live=True, approval=approval, idempotency_key="k2")["reason"], "approval_reused")
        self.assertEqual(client.write_calls, 1)


    def test_retries_and_concurrent_attempts_are_idempotent(self):
        client, flow = make(self.tmp)
        payload = {"name": "synthetic"}
        results = []
        approvals = [flow.issue_approval(payload, nonce=f"n-{i}") for i in range(6)]

        def attempt(approval):
            results.append(flow.run(payload, live=True, approval=approval, idempotency_key="same"))

        threads = [threading.Thread(target=attempt, args=(approval,)) for approval in approvals]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(client.write_calls, 1)
        self.assertEqual(sum(result["status"] == "written" for result in results), 1)
        self.assertEqual(sum(result["status"] == "duplicate" for result in results), 5)

        lines = [json.loads(line) for line in (self.tmp / "audit.jsonl").read_text().splitlines()]
        self.assertTrue(all("name" not in line for line in lines))
        self.assertTrue({line["event"] for line in lines} >= {"written", "duplicate"})

    def test_independent_workers_share_durable_reservation(self):
        client_a, flow_a = make(self.tmp)
        client_b, flow_b = make(self.tmp)
        payload = {"name": "synthetic"}
        results = []

        def attempt(flow, approval):
            results.append(flow.run(payload, live=True, approval=approval, idempotency_key="shared"))

        threads = [
            threading.Thread(target=attempt, args=(flow_a, flow_a.issue_approval(payload, "worker-a"))),
            threading.Thread(target=attempt, args=(flow_b, flow_b.issue_approval(payload, "worker-b"))),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(client_a.write_calls + client_b.write_calls, 1)
        self.assertEqual(sum(result["status"] == "written" for result in results), 1)
        self.assertEqual(sum(result["status"] == "duplicate" for result in results), 1)
