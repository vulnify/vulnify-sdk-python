import contextlib
import io
import json
import os
import stat
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from vulnify.cli import UNSUPPORTED_MESSAGE, main

STATE = {"calls": [], "status": 200, "body": {}}

ALLOW = {
    "id": "1",
    "decision": "ALLOW",
    "finalDecision": "ALLOW",
    "evaluatedDecision": "ALLOW",
    "monitored": False,
    "review": None,
    "riskLevel": "LOW",
    "riskScore": 5,
    "reasons": ["ok"],
    "policy": None,
    "dlpFindings": [],
    "lgpdCategories": [],
    "quotaExceeded": False,
    "sandbox": False,
}

POLICY = """\
apiVersion: vulnify.io/v1
kind: Policy
metadata:
  name: block-bulk-customer-export
spec:
  description: Block exports of more than 1000 customer records
  enabled: true
  action: EXPORT
  resource: CUSTOMER_PII
  condition:
    minRecords: 1001
  decision: BLOCK
  mode: ENFORCE
  approverRoles:
    - OWNER
    - ADMIN
"""

TEST_DOC = """\
apiVersion: vulnify.io/v1
kind: PolicyTest
metadata:
  name: export-rules
cases:
  - name: bulk export is blocked
    input:
      agent: support-bot
      action: EXPORT_DATA
      resource: customers-db
      recordsAffected: 5000
    expect:
      decision: BLOCK
      policy: block-bulk-customer-export
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return None

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _record(self, body=None):
        STATE["calls"].append({
            "method": self.command,
            "path": self.path,
            "body": body,
            "headers": dict(self.headers),
        })

    def do_GET(self):
        self._record()
        self._send(STATE["status"], STATE["body"])

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        body = json.loads(raw.decode() or "{}")
        self._record(body)
        self._send(STATE["status"], STATE["body"])


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        STATE.update(calls=[], status=200, body={})
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.work = Path(self.tmp.name) / "work"
        self.home.mkdir()
        self.work.mkdir()
        self._old = os.getcwd()
        os.chdir(self.work)
        self._env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        self._env.start()
        os.environ.pop("VULNIFY_API_KEY", None)
        os.environ.pop("VULNIFY_BASE_URL", None)

    def tearDown(self):
        self._env.stop()
        os.chdir(self._old)
        self.tmp.cleanup()

    def run_cli(self, argv, env=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            if env:
                with mock.patch.dict(os.environ, env):
                    code = main(argv)
            else:
                code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def write_creds(self, api_key="vln_test_k", base_url=None, mode=0o600):
        directory = self.home / ".config" / "vulnify"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "credentials.json"
        path.write_text(json.dumps({
            "apiKey": api_key,
            "baseUrl": base_url or self.url,
        }))
        os.chmod(path, mode)
        return path

    def test_help_and_version(self):
        code, out, _err = self.run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("vulnify policies apply", out)
        self.assertIn(UNSUPPORTED_MESSAGE, out)
        self.assertIn("0600", out)

        code, out, _err = self.run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "0.4.0")

        code, out, _err = self.run_cli([])
        self.assertEqual(code, 1)
        self.assertIn("vulnify init", out)

    def test_init_writes_examples_and_refuses_to_overwrite(self):
        code, out, _err = self.run_cli(["init"])
        self.assertEqual(code, 0)
        self.assertIn("credentials.json", out)
        self.assertIn("0600", out)
        policy = (self.work / "vulnify/policies/example.yaml").read_text()
        test = (self.work / "vulnify/tests/example.test.yaml").read_text()
        ignore = (self.work / "vulnify/.gitignore").read_text()
        self.assertIn("minRecords: 1001", policy)
        self.assertNotIn("recordsAffected:", policy)
        self.assertIn("action: EXPORT", policy)
        self.assertIn("resource: CUSTOMER_PII", policy)
        self.assertIn("kind: PolicyTest", test)
        self.assertIn("action: EXPORT_DATA", test)
        self.assertIn("0600", ignore)

        code, out, _err = self.run_cli(["policies", "validate"])
        self.assertEqual(code, 0, out)
        self.assertIn("Validated 1 policy", out)

        code, out, _err = self.run_cli(["init"])
        self.assertEqual(code, 1)
        self.assertIn("Refusing to overwrite", out)

    def test_validate_reports_file_line_for_placeholder_grammar(self):
        path = self.work / "bad.yaml"
        path.write_text(
            """\
apiVersion: vulnify.io/v1
kind: Policy
metadata:
  name: bad-export
spec:
  action: EXPORT_DATA
  resource: customers-db
  condition:
    recordsAffected:
      gt: 1000
  decision: BLOCK
"""
        )
        code, out, _err = self.run_cli(["policies", "validate", str(path)])
        self.assertEqual(code, 1)
        self.assertRegex(out, r"bad\.yaml:\d+:")
        self.assertIn("recordsAffected", out)
        self.assertIn("/spec/action", out)
        condition_line = next(line for line in out.splitlines() if "recordsAffected" in line)
        line_no = int(condition_line.split(":")[1])
        self.assertGreaterEqual(line_no, 9)

        code, out, _err = self.run_cli(["--json", "policies", "validate", str(path)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["exitCode"], 1)

    def test_grouped_conditions_and_bad_agent_id(self):
        path = self.work / "grouped.yaml"
        path.write_text(
            """\
apiVersion: vulnify.io/v1
kind: Policy
metadata:
  name: grouped
spec:
  action: EXPORT
  resource: ANY
  decision: REVIEW
  condition:
    minRecords: 1000
    maxRecords: 5000
    containsSensitiveData: true
    outsideBusinessHours: true
    destination: EXTERNAL
    destinationContains: gmail.com
    minRiskScore: 40
    allOf:
      - action: EXPORT_DATA
        agentIds:
          - 11111111-1111-4111-8111-111111111111
    anyOf:
      - destination: INTERNAL
  approverRoles:
    - OWNER
"""
        )
        code, out, _err = self.run_cli(["policies", "validate", str(path)])
        self.assertEqual(code, 0, out)

        path.write_text(path.read_text().replace("11111111-1111-4111-8111-111111111111", "support-bot"))
        code, out, _err = self.run_cli(["policies", "validate", str(path)])
        self.assertEqual(code, 1)
        self.assertIn("agentIds", out)

    def test_duplicate_policy_names(self):
        (self.work / "a.yaml").write_text(POLICY)
        (self.work / "b.yaml").write_text(POLICY)
        code, out, _err = self.run_cli(["policies", "validate", str(self.work)])
        self.assertEqual(code, 1)
        self.assertIn("Duplicate policy name", out)

    def test_login_stores_key_and_treats_401_as_auth_failure(self):
        STATE.update(status=404, body={"message": "Event not found", "statusCode": 404})
        code, out, _err = self.run_cli([
            "login", "--api-key", "vln_test_abc", "--base-url", self.url + "/",
        ])
        self.assertEqual(code, 0, out)
        creds = self.home / ".config" / "vulnify" / "credentials.json"
        self.assertEqual(stat.S_IMODE(creds.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(creds.parent.stat().st_mode), 0o700)
        self.assertEqual(json.loads(creds.read_text()), {
            "apiKey": "vln_test_abc",
            "baseUrl": self.url,
        })
        self.assertEqual(STATE["calls"][0]["path"], "/v1/events/00000000-0000-4000-8000-000000000000")
        self.assertEqual(STATE["calls"][0]["headers"]["Authorization"], "Bearer vln_test_abc")

        STATE.update(calls=[], status=401, body={"message": "Invalid API key", "statusCode": 401})
        code, out, _err = self.run_cli(["login", "--api-key", "nope", "--base-url", self.url])
        self.assertEqual(code, 5)
        self.assertIn("Invalid API key", out)
        self.assertEqual(json.loads(creds.read_text())["apiKey"], "vln_test_abc")

        STATE.update(calls=[], status=404, body={
            "message": "Cannot GET /v1/events/00000000-0000-4000-8000-000000000000",
        })
        code, out, _err = self.run_cli([
            "login", "--api-key", "vln_test_abc", "--base-url", self.url,
        ])
        self.assertEqual(code, 1)
        self.assertIn("no decision API", out)

    def test_check_exit_codes(self):
        self.write_creds(api_key="vln_test_file", base_url="https://file.example")
        STATE.update(status=200, body=ALLOW)
        code, out, _err = self.run_cli(
            [
                "check", "--agent", "support-bot", "--action", "EXPORT_DATA",
                "--resource", "customers-db", "--records", "12", "--destination", "EXTERNAL_EMAIL",
            ],
            {"VULNIFY_API_KEY": "vln_test_env", "VULNIFY_BASE_URL": self.url},
        )
        self.assertEqual(code, 0, out)
        self.assertIn("ALLOW", out)
        self.assertEqual(STATE["calls"][0]["path"], "/v1/events")
        self.assertEqual(STATE["calls"][0]["headers"]["Authorization"], "Bearer vln_test_env")
        self.assertEqual(STATE["calls"][0]["body"], {
            "agent": "support-bot",
            "action": "EXPORT_DATA",
            "resource": "customers-db",
            "destination": "EXTERNAL_EMAIL",
            "recordsAffected": 12,
        })

        self.write_creds(api_key="vln_test_file", base_url=self.url)
        STATE.update(calls=[], status=200, body={**ALLOW, "decision": "REVIEW", "finalDecision": "REVIEW"})
        code, _out, _err = self.run_cli(["check", "--agent", "a", "--action", "READ_DATA", "--resource", "r"])
        self.assertEqual(code, 2)

        STATE.update(calls=[], status=200, body={
            **ALLOW, "decision": "REVIEW", "finalDecision": "BLOCK", "reasons": ["denied"],
        })
        code, out, _err = self.run_cli(["check", "--agent", "a", "--action", "READ_DATA", "--resource", "r"])
        self.assertEqual(code, 3)
        self.assertIn("BLOCK", out)

        STATE.update(calls=[], status=401, body={"message": "Invalid API key"})
        code, _out, _err = self.run_cli(["check", "--agent", "a", "--action", "READ_DATA", "--resource", "r"])
        self.assertEqual(code, 5)

        code, out, _err = self.run_cli(
            ["check", "--agent", "a", "--action", "READ_DATA", "--resource", "r"],
            {"VULNIFY_BASE_URL": "http://127.0.0.1:1"},
        )
        self.assertEqual(code, 1)
        self.assertIn("failMode=closed", out)

        STATE.update(calls=[], status=200, body=ALLOW)
        code, _out, err = self.run_cli(
            ["check", "--agent", "a", "--action", "READ_DATA", "--resource", "r", "--sensitive"],
            {"VULNIFY_API_KEY": "vln_live_real", "VULNIFY_BASE_URL": self.url},
        )
        self.assertEqual(code, 0)
        self.assertIn("LIVE key", err)
        self.assertIn("--sensitive is not sent", err)
        self.assertNotIn("containsSensitiveData", STATE["calls"][-1]["body"])

        code, out, _err = self.run_cli(["--json", "check", "--agent", "a", "--action", "READ_DATA", "--resource", "r"])
        parsed = json.loads(out)
        self.assertEqual(parsed["finalDecision"], "ALLOW")
        self.assertEqual(parsed["exitCode"], 0)

    def test_pull_writes_yaml_and_exits_4_on_404(self):
        self.write_creds()
        STATE.update(status=200, body={
            "apiVersion": "vulnify.io/v1",
            "policies": [
                {
                    "name": "Zebra",
                    "id": "11111111-1111-4111-8111-111111111111",
                    "updatedAt": "2026-10-02T12:00:00.000Z",
                    "action": "READ",
                    "decision": "ALLOW",
                    "condition": {},
                },
                {
                    "name": "block-bulk-customer-export",
                    "id": "22222222-2222-4222-8222-222222222222",
                    "updatedAt": "2026-10-02T12:00:00.000Z",
                    "description": "Block exports of more than 1000 customer records",
                    "enabled": True,
                    "action": "EXPORT",
                    "resource": "CUSTOMER_PII",
                    "condition": {"minRecords": 1001},
                    "decision": "BLOCK",
                    "mode": "ENFORCE",
                    "approverRoles": ["OWNER", "ADMIN"],
                },
            ],
        })
        code, out, _err = self.run_cli(["policies", "pull", "--out", "out"])
        self.assertEqual(code, 0, out)
        self.assertIn("out/block-bulk-customer-export.yaml", out)
        self.assertIn("out/zebra.yaml", out)
        bulk = (self.work / "out" / "block-bulk-customer-export.yaml").read_text()
        self.assertIn("minRecords: 1001", bulk)
        self.assertIn("kind: Policy", bulk)
        self.assertIn("22222222-2222-4222-8222-222222222222", bulk)
        code, out, _err = self.run_cli(["policies", "validate", "out"])
        self.assertEqual(code, 0, out)

        STATE.update(calls=[], status=404, body={
            "message": "Cannot GET /v1/policies", "error": "Not Found", "statusCode": 404,
        })
        code, out, _err = self.run_cli(["policies", "pull"])
        self.assertEqual(code, 4)
        self.assertEqual(out.strip(), UNSUPPORTED_MESSAGE)

        code, out, _err = self.run_cli(["--json", "policies", "pull"])
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(out)["error"], UNSUPPORTED_MESSAGE)

        STATE.update(calls=[], status=401, body={"message": "Invalid API key"})
        code, _out, _err = self.run_cli(["policies", "pull"])
        self.assertEqual(code, 5)

        STATE.update(calls=[], status=429, body={"error": "rate_limited"})
        code, out, _err = self.run_cli(["policies", "pull"])
        self.assertEqual(code, 1)
        self.assertIn("rate_limited", out)

    def test_apply_posts_plan_and_skips_server_for_invalid_file(self):
        self.write_creds()
        (self.work / "policy.yaml").write_text(POLICY)
        STATE.update(status=200, body={
            "dryRun": True,
            "changes": [{"name": "block-bulk-customer-export", "op": "create"}],
        })
        code, out, _err = self.run_cli(["policies", "apply", "policy.yaml", "--dry-run", "--prune"])
        self.assertEqual(code, 0, out)
        self.assertIn("dry-run", out)
        self.assertIn("create", out)
        self.assertIn("block-bulk-customer-export", out)
        sent = STATE["calls"][0]
        self.assertEqual(sent["path"], "/v1/policies/apply")
        self.assertIs(sent["body"]["dryRun"], True)
        self.assertIs(sent["body"]["prune"], True)
        policy = sent["body"]["policies"][0]
        self.assertEqual(policy["name"], "block-bulk-customer-export")
        self.assertEqual(policy["action"], "EXPORT")
        self.assertEqual(policy["resource"], "CUSTOMER_PII")
        self.assertEqual(policy["condition"], {"minRecords": 1001})
        self.assertEqual(policy["decision"], "BLOCK")
        self.assertNotIn("id", policy)

        before = len(STATE["calls"])
        (self.work / "policy.yaml").write_text(POLICY.replace("action: EXPORT", "action: EXPORT_DATA"))
        code, _out, _err = self.run_cli(["policies", "apply", "policy.yaml"])
        self.assertEqual(code, 1)
        self.assertEqual(len(STATE["calls"]), before)

        (self.work / "policy.yaml").write_text(POLICY)
        STATE.update(calls=[], status=404, body={"message": "Cannot POST /v1/policies/apply"})
        code, out, _err = self.run_cli(["policies", "apply", "policy.yaml"])
        self.assertEqual(code, 4)
        self.assertEqual(out.strip(), UNSUPPORTED_MESSAGE)

        STATE.update(calls=[], status=400, body={
            "error": "validation_error",
            "fields": {"policies[0].action": "unknown action"},
        })
        code, out, _err = self.run_cli(["policies", "apply", "policy.yaml"])
        self.assertEqual(code, 1)
        self.assertIn("policies[0].action: unknown action", out)

        STATE.update(calls=[], status=403, body={
            "error": "forbidden",
            "message": "policies:apply requires an org-wide LIVE key",
        })
        code, out, _err = self.run_cli(["policies", "apply", "policy.yaml"])
        self.assertEqual(code, 5)
        self.assertIn("org-wide LIVE key", out)

    def test_test_pass_fail_and_local_policies(self):
        self.write_creds()
        (self.work / "vulnify" / "policies").mkdir(parents=True)
        (self.work / "vulnify" / "tests").mkdir(parents=True)
        (self.work / "vulnify" / "policies" / "example.yaml").write_text(POLICY)
        (self.work / "vulnify" / "tests" / "example.test.yaml").write_text(TEST_DOC)
        STATE.update(status=200, body={
            "results": [{
                "name": "bulk export is blocked",
                "decision": "BLOCK",
                "matchedPolicy": "block-bulk-customer-export",
                "riskScore": 80,
                "riskLevel": "HIGH",
                "reasons": ["records"],
                "pass": True,
            }],
        })
        code, out, _err = self.run_cli(["test"])
        self.assertEqual(code, 0, out)
        self.assertIn("PASS  bulk export is blocked", out)
        body = STATE["calls"][0]["body"]
        self.assertNotIn("policies", body)
        self.assertEqual(body["cases"][0]["name"], "bulk export is blocked")
        self.assertEqual(STATE["calls"][0]["path"], "/v1/policies/test")

        STATE.update(calls=[], status=200, body={
            "results": [{
                "name": "bulk export is blocked",
                "decision": "ALLOW",
                "matchedPolicy": None,
                "riskScore": 1,
                "riskLevel": "LOW",
                "reasons": [],
                "pass": False,
            }],
        })
        code, out, _err = self.run_cli(["test", "--local", "--json"])
        self.assertEqual(code, 1)
        sent = STATE["calls"][-1]["body"]
        self.assertEqual(len(sent["policies"]), 1)
        self.assertEqual(sent["policies"][0]["name"], "block-bulk-customer-export")
        parsed = json.loads(out)
        self.assertEqual(parsed["failed"], 1)
        self.assertEqual(parsed["exitCode"], 1)

        STATE.update(calls=[], status=404, body={"message": "Cannot POST /v1/policies/test"})
        code, out, _err = self.run_cli(["test"])
        self.assertEqual(code, 4)
        self.assertEqual(out.strip(), UNSUPPORTED_MESSAGE)

        STATE.update(calls=[], status=401, body={"error": "Unauthorized", "message": "Invalid API key"})
        code, _out, _err = self.run_cli(["test"])
        self.assertEqual(code, 5)

    def test_missing_key_exits_5(self):
        code, _out, _err = self.run_cli(["policies", "pull"])
        self.assertEqual(code, 5)
        (self.work / "policy.yaml").write_text(POLICY)
        code, _out, _err = self.run_cli(["policies", "apply", "policy.yaml"])
        self.assertEqual(code, 5)
        (self.work / "case.yaml").write_text(TEST_DOC)
        code, _out, _err = self.run_cli(["test", "case.yaml"])
        self.assertEqual(code, 5)
        code, _out, _err = self.run_cli(["check", "--agent", "a", "--action", "READ_DATA", "--resource", "r"])
        self.assertEqual(code, 5)
        code, _out, _err = self.run_cli(["login"])
        self.assertEqual(code, 5)

    def test_loose_credential_file_and_env_key_wins(self):
        path = self.write_creds(api_key="vln_test_file", base_url=self.url, mode=0o644)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        STATE.update(status=200, body=ALLOW)
        code, _out, _err = self.run_cli(
            ["check", "--agent", "a", "--action", "READ_DATA", "--resource", "r"],
            {"VULNIFY_API_KEY": "vln_test_env"},
        )
        self.assertEqual(code, 0)
        self.assertEqual(STATE["calls"][0]["headers"]["Authorization"], "Bearer vln_test_env")
        self.assertEqual(STATE["calls"][0]["path"], "/v1/events")
