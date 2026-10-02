# vulnify

Runtime authorization for AI agents. Before the agent exports or sends customer records, your app asks Vulnify. The decision is `ALLOW`, `REVIEW`, or `BLOCK`. The score is an integer from 0 to 100 and comes back with reasons.

Vulnify sees action metadata — agent, action, resource, destination, and record count — not the records. In monitor mode the event is stored and not enforced: obey `final_decision` when it is present, otherwise `decision`. `evaluated_decision` is what enforcement would have returned, and `monitored` is `True`. If Vulnify cannot be reached, the default is fail-closed.

The core install is the standard library only. Python 3.9+. The CLI is the `vulnify[cli]` extra.

Production API: https://api.vulnify.io

Documentation: https://docs.vulnify.io

## Install

```bash
pip install vulnify
pip install "vulnify[cli]"
```

The second command installs the `vulnify` console script. The core package does not depend on it.

## Production scenario

An agent is about to export customer records to an external destination. Call `check()` first.

- `ALLOW` runs the export.
- `REVIEW` stops and tells the caller a human must approve. The export does not run.
- `BLOCK` does not run the export.
- If Vulnify cannot be reached, `check()` returns `BLOCK` with `degraded=True`. The export does not run.

Set `VULNIFY_API_KEY`. With no `base_url`, this calls `https://api.vulnify.io`. For a local API, set `VULNIFY_BASE_URL=http://localhost:3000` or pass `base_url="http://localhost:3000"`. An explicit `base_url` wins over `VULNIFY_BASE_URL`.

```python
import os
import sys

from vulnify import Vulnify


def export_customer_records() -> None:
    """Replace the body with the real export. It runs only after ALLOW."""
    print("exporting customer records to the external destination")


def main() -> None:
    api_key = os.environ.get("VULNIFY_API_KEY")
    if not api_key:
        raise SystemExit("Set VULNIFY_API_KEY")

    # Local API: Vulnify(api_key=api_key, base_url="http://localhost:3000")
    vulnify = Vulnify(api_key=api_key)

    decision = vulnify.check(
        agent="SalesBot",
        action="EXPORT_DATA",
        resource="Customer Database",
        destination="EXTERNAL_EMAIL",
        records_affected=12000,
    )

    if decision.decision == "ALLOW":
        export_customer_records()
        return

    reasons = "; ".join(decision.reasons) or "no reason given"

    if decision.decision == "REVIEW":
        score = "unknown" if decision.risk_score is None else str(decision.risk_score)
        event_id = decision.id or "none"
        raise SystemExit(
            f"A human must approve this export before it runs (event {event_id}, score {score}). {reasons}"
        )

    if decision.degraded:
        raise SystemExit(f"Vulnify could not be reached. The export was not run. {reasons}")

    raise SystemExit(f"Export blocked. The export was not run. {reasons}")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(err, file=sys.stderr)
        raise SystemExit(1)
```

A `REVIEW` is approved on the Vulnify server (Slack, an MFA step-up, or a separate approver). This process does not approve it and does not poll. A separate MCP or HTTP gateway injects secrets only after `ALLOW`.

`guard(fn, **action)` runs `fn` only when the effective decision is `ALLOW` and raises `VulnifyBlockedError` for `REVIEW` and `BLOCK`. That effective value is `final_decision` when the API sent it, and `decision` otherwise. Pass `wait={"timeout": 300}` only when you mean to poll until a review resolves. `protect(**action)` is the same check as a decorator. Retries reuse the same `Idempotency-Key`, so a retry does not create a second event. `get_event` and `wait_for_review` use those same retries; if the API is still unavailable they raise `VulnifyError` instead of applying `fail_mode`.

## Decisions

- `ALLOW` — run the action. `risk_score` is 0–100. `reasons` explains the score.
- `REVIEW` — do not run the action yet. `review["status"]` starts as `PENDING`. Tell the caller a human must approve.
- `BLOCK` — do not run the action.

`decision` is the outcome stored on the event. It does not change when a review is resolved. `final_decision` is the field to obey after a review: `REVIEW` while it is pending, `ALLOW` when a human approves, and `BLOCK` when they deny it or it expires. `get_event` returns the same body as `check()`, including `final_decision`, `quota_exceeded`, `sandbox`, and `lgpd_categories`. An idempotent replay of a decision made before `finalDecision` shipped can omit it (`final_decision is None`). `wait_for_review` and `guard(..., wait=)` then treat review status `APPROVED` as the go signal, and `DENIED` or `EXPIRED` as a block.

Follow `final_decision` in monitor mode when it is present, otherwise `decision`. An invalid API key, an unknown agent or resource, a rejected payload, or a body the API refuses as too large (`413`) raises `VulnifyError`. The same is true of any other HTTP 4xx except `408` and `429`. `fail_mode="open"` does not swallow those errors and does not retry them.

Optional `content` is scanned for sensitive data and is not stored. Matches return on `dlp_findings`.

## Fail-closed

`fail_mode` defaults to `"closed"`. A timeout, a network error, `408`, `429`, or a `5xx` becomes `decision="BLOCK"`, `degraded=True`, and a reason beginning with `Vulnify unavailable`. The scenario above does not call `export_customer_records()`. Set `fail_mode="open"` only when an outage should let the action through. A `413` or any other non-retryable `4xx` never takes that path.

Audit events are hash-chained. SIEM export is JSON or CEF. Evidence in the product maps to LGPD, ISO/IEC 42001, NIST AI RMF, and the EU AI Act. That mapping is not a certification.

## Adapters

`vulnify.adapters` is duck-typed and does not import a framework until an adapter needs a type from that package. The core install has no runtime dependencies. Samples are in `examples/`.

CrewAI (`guard_crewai_tool`, `crewai_before_tool_call`) and LangGraph (`langgraph_tool_guard`, `alanggraph_tool_guard`) take a `describe` callback that maps tool arguments to `check` keywords. `on_blocked="message"` (the default for tool wrappers) returns Vulnify's reasons to the agent. `"raise"` raises `VulnifyBlockedError`.

### LangChain

```bash
pip install 'vulnify[langchain]'
```

`guard_langchain_tool` guards `_run` / `_arun` on a `BaseTool`, so `invoke` checks once. A tool that only has `invoke` or `call` is guarded on those methods.

```python
from vulnify.adapters import guard_langchain_tool

export_tool = guard_langchain_tool(vulnify, export_tool, describe_export)
```

### OpenAI Agents

```bash
pip install 'vulnify[openai-agents]'
```

`guard_openai_agents_tool` wraps a Python `FunctionTool`. `describe` sees the parsed JSON arguments. The model receives the block text instead of the tool running. `on_blocked="raise"` rethrows.

```python
from agents import function_tool

from vulnify.adapters import guard_openai_agents_tool

@function_tool
def export_customers(rows: int) -> str:
    """Export customer records."""
    return f"exported {rows}"

export_customers = guard_openai_agents_tool(vulnify, export_customers, describe_export)
```

### MCP

```bash
pip install 'vulnify[mcp]'
```

`guard_mcp_handler` wraps a tool function before you register it on `MCPServer` (mcp 2; the older name was FastMCP). `guard_mcp_client` wraps `session.call_tool`. A blocked call returns an MCP error result (`CallToolResult` when `mcp` is installed) and does not raise `VulnifyBlockedError`. Tools omitted from the client `describe` map are forwarded unchanged.

```python
from mcp.server import MCPServer

from vulnify.adapters import guard_mcp_client, guard_mcp_handler

async def export_customers(rows: int) -> str:
    """Export customer records."""
    return f"exported {rows}"

server = MCPServer("sales")
server.tool()(guard_mcp_handler(vulnify, describe_export, export_customers))

session = guard_mcp_client(vulnify, session, {"export_customers": describe_export})
```

A `REVIEW` uses `final_decision` on every adapter: `ALLOW` runs the tool, and `BLOCK` does not.

The npm SDK also ships a Vercel AI SDK helper. That framework has no Python counterpart, so this package does not include it.

## Webhooks

Vulnify signs each delivery with HMAC-SHA256. The key is the endpoint secret as UTF-8, including the `whsec_` prefix. It is not base64-decoded. The signed message is the unix timestamp, a dot, and the raw body bytes. `X-Vulnify-Signature` looks like `t=<unix seconds>,v1=<hex>`. During a secret rotation the header can carry more than one `v1`; any match is enough. A timestamp exactly 300 seconds off is still valid. Pass the raw body, not JSON you parsed and dumped again.

`X-Vulnify-Delivery` is the delivery id (`event.id`). Dedupe retries on it. `X-Vulnify-Attempt` starts at 1. `X-Vulnify-Event` is the primary type and matches `event.type`. Those three headers are not signed. Trust the body after the signature check.

```python
from vulnify import WebhookVerificationError, construct_webhook_from_request

try:
    event = construct_webhook_from_request(secret, headers, raw_body)
except WebhookVerificationError:
    return 400  # 408, 429, and 5xx are retried; any other 4xx stops them

# event.id is the delivery id. event.event_id is the security event, anomaly, or test id.
if event.type in ("BLOCK", "REVIEW", "CRITICAL"):
    obey = event.data.final_decision  # ALLOW, REVIEW, or BLOCK
```

`verify_webhook_signature(secret, signature_header, raw_body)` only checks the signature and raises `WebhookVerificationError`. `parse_webhook(raw_body)` returns a `DecisionWebhook`, `AnomalyWebhook`, or `TestWebhook`. `construct_webhook` does both. `decision` on a decision payload is what was stored. `final_decision` is the outcome to obey.

Flask uses `request.get_data()`, FastAPI uses `await request.body()`, and Django uses `request.body`. Short samples are in `examples/flask_webhook.py`, `examples/fastapi_webhook.py`, and `examples/django_webhook.py`.

## CLI

`pip install "vulnify[cli]"` adds the `vulnify` command. It is the same command set as the npm CLI: `init`, `login`, `check`, `policies validate`, `policies pull`, `policies apply`, and `test`. There is no telemetry.

Credentials are written to `~/.config/vulnify/credentials.json` with mode 0600. `VULNIFY_API_KEY` and `VULNIFY_BASE_URL` override that file. The default base URL is `https://api.vulnify.io`.

| Exit code | Meaning |
| --- | --- |
| 0 | Success, or `ALLOW` from `check` |
| 1 | Validation error, test failure, or another command failure |
| 2 | `REVIEW` from `check` |
| 3 | `BLOCK` from `check` |
| 4 | This server has no policies-as-code API yet |
| 5 | Authentication error |

```bash
vulnify init
vulnify login --api-key "$VULNIFY_API_KEY"
vulnify check --agent support-bot --action EXPORT_DATA --resource customers-db --records 5000
vulnify policies validate
vulnify policies pull --out vulnify/policies
vulnify policies apply --dry-run
vulnify policies apply --prune
vulnify test --local
```

Every command accepts `--json`. `vulnify --version` prints the package version. `check` prints a warning on stderr when the key starts with `vln_live_`, because that call records a real event. `--destination` and `--records` map to the decision API. `--sensitive` is accepted so the flags match the npm CLI; the decision API has no boolean for it, and the CLI warns that the flag is not sent. `check` exits from `finalDecision` when the API sends it, and from `decision` otherwise. An unreachable API is exit 1 (`failMode=closed`), not exit 3.

`login` checks the key with `GET /v1/events/00000000-0000-4000-8000-000000000000`. HTTP 200, 403, or 404 means the key was accepted. HTTP 401 is exit 5. A 404 whose message starts with `Cannot GET` means that base URL has no decision API and is exit 1. The credentials directory is mode 0700.

`policies pull`, `policies apply`, and `test` call `/v1/policies`, `/v1/policies/apply`, and `/v1/policies/test`. A 404 prints exactly `This Vulnify server does not support policies as code yet` and exits 4. Apply with anything other than an org-wide LIVE key is rejected by the API; the CLI exits 5. `pull` writes one file per policy, keeps `metadata.id` and `metadata.updatedAt`, and `apply` does not send those fields back.

`init` writes `vulnify/policies/example.yaml`, `vulnify/tests/example.test.yaml`, and `vulnify/.gitignore`, and refuses to overwrite any of them. Several documents may share a file, separated by `---`. `policies validate` is offline and reports `file:line` errors against `vulnify/schema/policies.v1.json`, which is a byte-identical copy of `schema/policies.v1.json` from the npm SDK.

A policy `action` is the action family: `ANY`, `READ`, `WRITE`, `DELETE`, or `EXPORT`. `resource` is a resource type (`ANY`, `PUBLIC`, `INTERNAL`, `SENSITIVE`, `CUSTOMER_PII`, `FINANCIAL`, `EMPLOYEE`) or null. A condition uses the dashboard fields: `minRecords` and `maxRecords` are inclusive bounds on `recordsAffected` (`minRecords: 1001` is more than 1000 records), plus `destination` (`EXTERNAL` or `INTERNAL`), `destinationContains`, `containsSensitiveData`, `minRiskScore`, `outsideBusinessHours`, `agentIds`, and grouped `allOf` / `anyOf`. `kind: PolicyTest` cases use the event action (`EXPORT_DATA` and the rest) and a resource name.

`vulnify test --local` sends the cases plus the Policy documents in `vulnify/policies`. Without `--local`, only the cases are sent. `pass: true` is PASS, `pass: null` is SKIP, and any other `pass` value is FAIL. The exit code is 1 when any case fails.

## Development

```bash
pip install -e ".[dev,cli]"
pytest
```

## License

MIT. Copyright 2026 Vulnify.
