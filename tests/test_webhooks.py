import hashlib
import hmac
import json
import shutil
import subprocess
import unittest

from vulnify import (
    AnomalyWebhook,
    DecisionWebhook,
    WebhookPayloadError,
    WebhookVerificationError,
    construct_webhook,
    construct_webhook_from_request,
    header_value,
    parse_webhook,
    verify_webhook_signature,
)
from vulnify.webhooks import TestWebhook as WebhookTestDelivery

# Node createHmac('sha256', 'whsec_a').update('1800000000.{"id":"d1","type":"BLOCK"}').digest('hex')
# This is the same call the npm verifyWebhookSignature helper makes.
NODE_VECTOR = "ef9e8005af6eecdb3386f0d793dab026faf6dddce90d598b1cd0122415f93b15"
SECRET = "whsec_a"
BODY = b'{"id":"d1","type":"BLOCK"}'
NOW = 1_800_000_000


def sign(secret, timestamp, body):
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    message = str(timestamp).encode("ascii") + b"." + raw
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (timestamp, digest)


DELIVERY = "11111111-1111-4111-8111-111111111111"
EVENT = "22222222-2222-4222-8222-222222222222"


def decision_body():
    return json.dumps(
        {
            "id": DELIVERY,
            "type": "BLOCK",
            "types": ["BLOCK", "CRITICAL"],
            "eventId": EVENT,
            "createdAt": "2026-10-02T20:00:00Z",
            "data": {
                "id": EVENT,
                "agent": "SalesBot",
                "action": "EXPORT_DATA",
                "resource": "Customer Database",
                "riskScore": 90,
                "riskLevel": "CRITICAL",
                "decision": "REVIEW",
                "finalDecision": "BLOCK",
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")


class VerifyTests(unittest.TestCase):
    def test_accepts_the_npm_hmac_vector_for_bytes_and_str(self):
        header = "t=%d,v1=%s" % (NOW, NODE_VECTOR)
        verify_webhook_signature(SECRET, header, BODY, now=NOW)
        verify_webhook_signature(SECRET, header, BODY.decode("utf-8"), now=NOW)
        self.assertEqual(sign(SECRET, NOW, BODY), header)

    def test_live_node_matches_the_npm_helper_when_node_is_installed(self):
        if shutil.which("node") is None:
            self.skipTest("node is not installed")
        script = (
            "const {createHmac}=require('crypto');"
            "const secret='whsec_a';"
            "const body='{\"id\":\"d1\",\"type\":\"BLOCK\"}';"
            "process.stdout.write(createHmac('sha256', secret).update(`1800000000.${body}`).digest('hex'));"
        )
        digest = subprocess.check_output(["node", "-e", script], text=True)
        self.assertEqual(digest, NODE_VECTOR)

    def test_accepts_any_v1_and_rejects_when_none_match(self):
        good = NODE_VECTOR
        wrong = "ab" * 32
        verify_webhook_signature(SECRET, "t=%d,v1=%s,v1=%s" % (NOW, wrong, good), BODY, now=NOW)
        verify_webhook_signature(SECRET, "t=%d,v1=%s, v1=%s" % (NOW, good, wrong), BODY, now=NOW)
        with self.assertRaises(WebhookVerificationError) as raised:
            verify_webhook_signature(SECRET, "t=%d,v1=%s,v1=%s" % (NOW, wrong, "cd" * 32), BODY, now=NOW)
        self.assertIn("does not match", str(raised.exception))

    def test_tolerance_allows_exactly_300_seconds_and_rejects_301(self):
        verify_webhook_signature(SECRET, sign(SECRET, NOW - 300, BODY), BODY, now=NOW)
        verify_webhook_signature(SECRET, sign(SECRET, NOW + 300, BODY), BODY, now=NOW)
        with self.assertRaises(WebhookVerificationError) as past:
            verify_webhook_signature(SECRET, sign(SECRET, NOW - 301, BODY), BODY, now=NOW)
        self.assertIn("tolerance", str(past.exception))
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(SECRET, sign(SECRET, NOW + 301, BODY), BODY, now=NOW)

    def test_rejects_a_wrong_secret_tampered_body_and_malformed_headers(self):
        header = sign(SECRET, NOW, BODY)
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature("whsec_b", header, BODY, now=NOW)
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(SECRET, header, BODY.replace(b"BLOCK", b"ALLOW"), now=NOW)
        with self.assertRaises(WebhookVerificationError) as missing:
            verify_webhook_signature(SECRET, None, BODY, now=NOW)
        self.assertIn("Missing", str(missing.exception))
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(SECRET, "v1=abc", BODY, now=NOW)
        with self.assertRaises(WebhookVerificationError):
            verify_webhook_signature(SECRET, "t=1.5,v1=%s" % NODE_VECTOR, BODY, now=NOW)

    def test_secret_is_utf8_not_base64(self):
        secret = "whsec_YQ=="
        body = b"{}"
        header = sign(secret, NOW, body)
        verify_webhook_signature(secret, header, body, now=NOW)
        decoded_key = hmac.new(b"a", b"%d.{}" % NOW, hashlib.sha256).hexdigest()
        self.assertNotEqual(header.split("=", 2)[-1], decoded_key)


class ParseTests(unittest.TestCase):
    def test_construct_reads_decision_final_decision_and_event_id(self):
        raw = decision_body()
        event = construct_webhook(SECRET, sign(SECRET, NOW, raw), raw, now=NOW)
        self.assertIsInstance(event, DecisionWebhook)
        self.assertEqual(event.id, DELIVERY)
        self.assertEqual(event.event_id, EVENT)
        self.assertEqual(event.types, ("BLOCK", "CRITICAL"))
        self.assertEqual(event.data.decision, "REVIEW")
        self.assertEqual(event.data.final_decision, "BLOCK")
        self.assertEqual(event.data.risk_score, 90)

    def test_parses_anomaly_and_test_deliveries(self):
        anomaly = {
            "id": DELIVERY,
            "type": "ANOMALY",
            "types": ["ANOMALY"],
            "eventId": EVENT,
            "createdAt": "2026-10-02T20:00:00Z",
            "data": {
                "id": EVENT,
                "kind": "VOLUME_SPIKE",
                "severity": "HIGH",
                "message": "Export volume jumped",
                "agentId": EVENT,
                "messageCode": "anomaly.volume_spike",
                "messageParams": {"count": 12, "note": None},
            },
        }
        parsed = parse_webhook(json.dumps(anomaly).encode("utf-8"))
        self.assertIsInstance(parsed, AnomalyWebhook)
        self.assertEqual(parsed.data.kind, "VOLUME_SPIKE")
        self.assertEqual(parsed.data.message_params["count"], 12)
        self.assertIsNone(parsed.data.message_params["note"])

        test = {
            "id": DELIVERY,
            "type": "TEST",
            "types": ["TEST"],
            "eventId": "test-" + DELIVERY,
            "createdAt": "2026-10-02T20:00:00Z",
            "data": {
                "message": "Test event from Vulnify",
                "webhookId": EVENT,
                "organizationId": EVENT,
            },
        }
        parsed_test = parse_webhook(json.dumps(test).encode("utf-8"))
        self.assertIsInstance(parsed_test, WebhookTestDelivery)
        self.assertEqual(parsed_test.event_id, "test-" + DELIVERY)
        self.assertEqual(parsed_test.data.webhook_id, EVENT)

    def test_rejects_a_decision_that_omits_final_decision(self):
        raw = json.loads(decision_body().decode("utf-8"))
        del raw["data"]["finalDecision"]
        with self.assertRaises(WebhookPayloadError) as raised:
            parse_webhook(json.dumps(raw).encode("utf-8"))
        self.assertIn("finalDecision", str(raised.exception))

    def test_request_helper_finds_a_lowercase_signature_header(self):
        raw = decision_body()
        headers = {"x-vulnify-signature": sign(SECRET, NOW, raw), "X-Vulnify-Delivery": DELIVERY}
        event = construct_webhook_from_request(SECRET, headers, raw, now=NOW)
        self.assertEqual(event.id, DELIVERY)
        self.assertEqual(header_value(headers, "X-Vulnify-Delivery"), DELIVERY)
        with self.assertRaises(WebhookVerificationError):
            construct_webhook_from_request(SECRET, {}, raw, now=NOW)


if __name__ == "__main__":
    unittest.main()
