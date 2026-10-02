import json
import os
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from vulnify import Vulnify, VulnifyBlockedError, VulnifyError

STATE = {"calls": [], "reply": None, "status": 200, "review_statuses": [], "final_decisions": []}


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
        if STATE["status"] != 200:
            self._send(STATE["status"], STATE["reply"] if isinstance(STATE["reply"], dict) else {})
            return
        status = STATE["review_statuses"].pop(0) if STATE["review_statuses"] else "PENDING"
        body = {**STATE["reply"], "review": {"status": status}}
        if STATE["final_decisions"]:
            body["finalDecision"] = STATE["final_decisions"].pop(0)
        self._send(200, body)


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
        STATE.update(calls=[], status=200, reply=decision("ALLOW"), review_statuses=[], final_decisions=[])
        self.v = Vulnify("vln_live_x", base_url=self.url, timeout=2, retries=0)

    def test_default_base_url_is_production_and_stays_overridable(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VULNIFY_BASE_URL", None)
            self.assertEqual(Vulnify("k").base_url, "https://api.vulnify.io")
        with mock.patch.dict(os.environ, {"VULNIFY_BASE_URL": "http://localhost:3000/"}):
            self.assertEqual(Vulnify("k").base_url, "http://localhost:3000")
            self.assertEqual(Vulnify("k", base_url="https://api.vulnify.io/").base_url, "https://api.vulnify.io")
        with self.assertRaises(ValueError):
            Vulnify("k", base_url="  ")

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

    def test_payload_too_large_raises_and_is_not_retried_or_failed_open(self):
        STATE["status"] = 413
        STATE["reply"] = {"statusCode": 413, "message": "request entity too large"}
        client = Vulnify("k", base_url=self.url, fail_mode="open", retries=2)
        with mock.patch("vulnify.client.time.sleep") as sleep:
            with self.assertRaises(VulnifyError) as ctx:
                client.check(agent="A", action="EXPORT_DATA", content="x" * 20)
        self.assertIn("413", str(ctx.exception))
        self.assertIn("request entity too large", str(ctx.exception))
        self.assertEqual(len(STATE["calls"]), 1)
        sleep.assert_not_called()
        self.assertIs(type(ctx.exception), VulnifyError)

    def test_other_non_retryable_4xx_raise_while_408_and_429_stay_retryable(self):
        STATE["status"] = 422
        STATE["reply"] = {"message": "Unprocessable"}
        with mock.patch("vulnify.client.time.sleep") as sleep:
            with self.assertRaises(VulnifyError) as ctx:
                Vulnify("k", base_url=self.url, fail_mode="open", retries=2).check(agent="A", action="READ_DATA", resource="R")
        self.assertIn("422", str(ctx.exception))
        self.assertEqual(len(STATE["calls"]), 1)
        sleep.assert_not_called()

        STATE.update(calls=[], status=408, reply={})
        with mock.patch("vulnify.client.time.sleep") as sleep:
            opened = Vulnify("k", base_url=self.url, fail_mode="open", retries=1).check(agent="A", action="READ_DATA", resource="R")
        self.assertEqual((opened.decision, opened.degraded), ("ALLOW", True))
        self.assertEqual(len(STATE["calls"]), 2)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.05])

        STATE.update(calls=[], status=429, reply={"message": "Too Many Requests"})
        with mock.patch("vulnify.client.time.sleep") as sleep:
            closed = Vulnify("k", base_url=self.url, retries=2).check(agent="A", action="READ_DATA", resource="R")
        self.assertEqual((closed.decision, closed.degraded), ("BLOCK", True))
        self.assertEqual(len(STATE["calls"]), 3)
        self.assertEqual(len({c["headers"]["Idempotency-Key"] for c in STATE["calls"]}), 1)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.05, 0.1])

    def test_validation_messages_are_joined(self):
        STATE["status"] = 400
        STATE["reply"] = {"message": ["property extra should not exist", "action must be a valid enum"]}
        with self.assertRaises(VulnifyError) as ctx:
            self.v.check(agent="A", action="EXPORT_DATA", resource="R")
        text = str(ctx.exception)
        self.assertIn("property extra should not exist; action must be a valid enum", text)
        self.assertNotIn("['property extra", text)

    def test_final_decision_is_mapped_and_optional(self):
        STATE["reply"] = decision(
            "ALLOW",
            finalDecision="ALLOW",
            quotaExceeded=True,
            sandbox=True,
            lgpdCategories=["IDENTIFICATION"],
        )
        checked = self.v.check(agent="A", action="READ_DATA", resource="R")
        self.assertEqual(checked.final_decision, "ALLOW")
        self.assertTrue(checked.quota_exceeded)
        self.assertTrue(checked.sandbox)
        self.assertEqual(checked.lgpd_categories, ["IDENTIFICATION"])

        STATE["reply"] = decision("REVIEW", quotaExceeded=False, sandbox=True, lgpdCategories=["FINANCIAL"])
        STATE["review_statuses"] = ["APPROVED"]
        STATE["final_decisions"] = ["ALLOW"]
        read = self.v.get_event("evt-1")
        self.assertEqual(read.decision, "REVIEW")
        self.assertEqual(read.final_decision, "ALLOW")
        self.assertFalse(read.quota_exceeded)
        self.assertTrue(read.sandbox)
        self.assertEqual(read.lgpd_categories, ["FINANCIAL"])
        self.assertEqual(read.review["status"], "APPROVED")

        STATE["reply"] = decision("REVIEW")
        STATE["review_statuses"] = ["PENDING"]
        replay = Vulnify("vln_test_x", base_url=self.url, retries=0).get_event("evt-1")
        self.assertIsNone(replay.final_decision)
        self.assertIs(replay.sandbox, False)
        self.assertEqual(replay.decision, "REVIEW")

    def test_wait_and_guard_follow_final_decision(self):
        STATE["reply"] = decision("REVIEW", finalDecision="REVIEW")
        STATE["final_decisions"] = ["REVIEW", "ALLOW"]
        self.assertEqual(
            self.v.guard(lambda: "sent", wait={"timeout": 5, "poll": 0.01}, agent="A", action="SEND_EMAIL", resource="R"),
            "sent",
        )

        STATE.update(calls=[], final_decisions=[], review_statuses=["PENDING"])
        STATE["reply"] = decision("REVIEW", finalDecision="ALLOW")
        self.assertEqual(self.v.wait_for_review("evt-1", timeout=5, poll=0.01), "ALLOW")

        STATE.update(calls=[], final_decisions=["BLOCK"], review_statuses=["DENIED"])
        STATE["reply"] = decision("REVIEW", finalDecision="REVIEW")
        with self.assertRaises(VulnifyBlockedError):
            self.v.guard(lambda: "sent", wait={"timeout": 5, "poll": 0.01}, agent="A", action="SEND_EMAIL", resource="R")
        STATE.update(final_decisions=[], review_statuses=["EXPIRED"])
        STATE["reply"] = decision("REVIEW", finalDecision="BLOCK")
        self.assertEqual(self.v.wait_for_review("evt-1", timeout=5, poll=0.01), "BLOCK")

        # finalDecision REVIEW keeps waiting even if the review status is already APPROVED.
        STATE.update(calls=[], final_decisions=["REVIEW"], review_statuses=["APPROVED"])
        STATE["reply"] = decision("REVIEW", finalDecision="REVIEW")
        self.assertEqual(self.v.wait_for_review("evt-1", timeout=0.05, poll=0.02), "TIMEOUT")

        # An approved replay can already be ALLOW, so guard does not need to poll.
        STATE["reply"] = decision("REVIEW", finalDecision="ALLOW")
        self.assertEqual(self.v.guard(lambda: "sent", agent="A", action="SEND_EMAIL", resource="R"), "sent")
        STATE["reply"] = decision("REVIEW", finalDecision="BLOCK", reasons=["denied"])
        ran = []
        with self.assertRaises(VulnifyBlockedError):
            self.v.guard(lambda: ran.append(1), wait={"timeout": 5, "poll": 0.01}, agent="A", action="SEND_EMAIL", resource="R")
        self.assertEqual(ran, [])

    def test_get_event_retries_transient_failures_then_raises_vulnify_error(self):
        STATE["status"] = 503
        STATE["reply"] = {}
        with mock.patch("vulnify.client.time.sleep") as sleep:
            with self.assertRaises(VulnifyError) as ctx:
                Vulnify("k", base_url=self.url, fail_mode="open", retries=2).get_event("evt-1")
        self.assertIs(type(ctx.exception), VulnifyError)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIn("503", str(ctx.exception))
        self.assertIn("unavailable", str(ctx.exception))
        self.assertEqual(len(STATE["calls"]), 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.05, 0.1])

        STATE.update(calls=[], status=429, reply={"message": "Too Many Requests"})
        with mock.patch("vulnify.client.time.sleep"):
            with self.assertRaises(VulnifyError) as ctx:
                Vulnify("k", base_url=self.url, fail_mode="open", retries=1).wait_for_review("evt-1", timeout=5, poll=0.01)
        self.assertIn("429", str(ctx.exception))
        self.assertEqual(len(STATE["calls"]), 2)

        STATE.update(calls=[], status=404, reply={"message": "Event not found"})
        with self.assertRaises(VulnifyError) as ctx:
            Vulnify("k", base_url=self.url, retries=2).get_event("missing")
        self.assertIn("Event not found", str(ctx.exception))
        self.assertEqual(len(STATE["calls"]), 1)

    def test_get_event_network_error_raises_vulnify_error(self):
        with mock.patch("vulnify.client.urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with mock.patch("vulnify.client.time.sleep") as sleep:
                with self.assertRaises(VulnifyError) as ctx:
                    Vulnify("k", base_url="http://127.0.0.1:9", retries=1, timeout=0.2).get_event("evt-1")
        self.assertIs(type(ctx.exception), VulnifyError)
        self.assertIn("unavailable", str(ctx.exception))
        self.assertIn("down", str(ctx.exception))
        self.assertEqual(sleep.call_count, 1)

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
