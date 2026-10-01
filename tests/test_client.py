import json
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from vulnify import Vulnify, VulnifyBlockedError, VulnifyError

STATE = {"calls": [], "reply": None, "status": 200, "review_statuses": []}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        STATE["calls"].append({"path": self.path, "body": body, "headers": dict(self.headers)})
        self._send(STATE["status"], STATE["reply"])

    def do_GET(self):
        STATE["calls"].append({"path": self.path, "headers": dict(self.headers)})
        status = STATE["review_statuses"].pop(0) if STATE["review_statuses"] else "PENDING"
        self._send(200, {**STATE["reply"], "review": {"status": status}})


def decision(d, **extra):
    return {"id": "evt-1", "decision": d, "evaluatedDecision": d, "monitored": False, "riskLevel": "LOW",
            "riskScore": 5, "reasons": ["r"], "policy": None, "review": None, **extra}


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        STATE.update(calls=[], status=200, reply=decision("ALLOW"), review_statuses=[])
        self.v = Vulnify("vln_live_x", base_url=self.url, timeout=2, retries=0)

    def test_check_sends_key_payload_and_idempotency_key(self):
        r = self.v.check(agent="SalesBot", action="EXPORT_DATA", resource="Customer Database", records_affected=12)
        self.assertEqual(r.decision, "ALLOW")
        call = STATE["calls"][0]
        self.assertEqual(call["body"], {"agent": "SalesBot", "action": "EXPORT_DATA", "resource": "Customer Database", "recordsAffected": 12})
        self.assertEqual(call["headers"]["Authorization"], "Bearer vln_live_x")
        self.assertTrue(call["headers"]["Idempotency-Key"])

    def test_guard_runs_only_when_allowed(self):
        ran = []
        self.assertEqual(self.v.guard(lambda: ran.append(1) or "ok", agent="A", action="READ_DATA", resource="R"), "ok")
        STATE["reply"] = decision("BLOCK", reasons=["External destination"])
        with self.assertRaises(VulnifyBlockedError) as ctx:
            self.v.guard(lambda: ran.append(2), agent="A", action="EXPORT_DATA", resource="R")
        self.assertIn("External destination", str(ctx.exception))
        self.assertEqual(ran, [1])

    def test_review_with_wait(self):
        STATE["reply"] = decision("REVIEW", review={"status": "PENDING"})
        STATE["review_statuses"] = ["PENDING", "APPROVED"]
        self.assertEqual(self.v.guard(lambda: "sent", wait={"timeout": 5, "poll": 0.01}, agent="A", action="SEND_EMAIL", resource="R"), "sent")
        STATE["review_statuses"] = ["DENIED"]
        with self.assertRaises(VulnifyBlockedError):
            self.v.guard(lambda: "sent", wait={"timeout": 5, "poll": 0.01}, agent="A", action="SEND_EMAIL", resource="R")
        # Without wait, REVIEW is never allowed to proceed.
        with self.assertRaises(VulnifyBlockedError):
            self.v.guard(lambda: "sent", agent="A", action="SEND_EMAIL", resource="R")

    def test_wait_for_review_times_out(self):
        STATE["reply"] = decision("REVIEW")
        self.assertEqual(self.v.wait_for_review("evt-1", timeout=0.05, poll=0.02), "TIMEOUT")

    def test_config_errors_are_loud_even_in_fail_open(self):
        STATE["status"], STATE["reply"] = 401, {"message": "Invalid API key"}
        with self.assertRaises(VulnifyError):
            Vulnify("bad", base_url=self.url, fail_mode="open", retries=0).check(agent="A", action="READ_DATA", resource="R")

    def test_fail_modes_and_retries_share_the_idempotency_key(self):
        STATE["status"], STATE["reply"] = 503, {}
        closed = Vulnify("k", base_url=self.url, retries=2).check(agent="A", action="READ_DATA", resource="R")
        self.assertEqual((closed.decision, closed.degraded), ("BLOCK", True))
        keys = {c["headers"]["Idempotency-Key"] for c in STATE["calls"]}
        self.assertEqual(len(STATE["calls"]), 3)
        self.assertEqual(len(keys), 1)
        opened = Vulnify("k", base_url=self.url, fail_mode="open", retries=0).check(agent="A", action="READ_DATA", resource="R")
        self.assertEqual(opened.decision, "ALLOW")

    def test_unreachable_server_follows_fail_mode(self):
        r = Vulnify("k", base_url="http://127.0.0.1:1", timeout=0.2, retries=0).check(agent="A", action="READ_DATA", resource="R")
        self.assertTrue(r.degraded)
        self.assertEqual(r.decision, "BLOCK")

    def test_fail_closed_does_not_run_the_export_without_network(self):
        exported = []

        def export_customer_records():
            exported.append(True)

        with mock.patch("vulnify.client.urllib.request.urlopen", side_effect=urllib.error.URLError("unreachable")):
            decision = Vulnify("k", base_url="https://api.vulnify.io", timeout=0.2, retries=0).check(
                agent="SalesBot",
                action="EXPORT_DATA",
                resource="Customer Database",
                destination="EXTERNAL_EMAIL",
                records_affected=12000,
            )

        self.assertEqual(decision.decision, "BLOCK")
        self.assertTrue(decision.degraded)
        self.assertIsNone(decision.id)
        self.assertIn("fail_mode=closed", decision.reasons[0])
        if decision.decision == "ALLOW":
            export_customer_records()
        self.assertEqual(exported, [])

    def test_protect_decorator(self):
        @self.v.protect(agent="A", action="READ_DATA", resource="R")
        def load(x):
            return x * 2

        self.assertEqual(load(4), 8)
        STATE["reply"] = decision("BLOCK")
        with self.assertRaises(VulnifyBlockedError):
            load(1)


if __name__ == "__main__":
    unittest.main()
