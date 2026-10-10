<p align="center">
  <a href="https://vulnify.io">
    <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk-python/main/docs/assets/banner.png" alt="Vulnify: decide every AI agent action before it runs" width="100%">
  </a>
</p>

<h1 align="center">Vulnify Python SDK</h1>

<p align="center">
  <strong>Ask Vulnify before your AI agent acts. Get <code>ALLOW</code>, <code>REVIEW</code>, or <code>BLOCK</code>, with a risk score and the reasons.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/vulnify/"><img src="https://img.shields.io/pypi/v/vulnify?color=3D6DFF&label=pypi" alt="PyPI version"></a>
  <a href="https://pypi.org/project/vulnify/"><img src="https://img.shields.io/pypi/pyversions/vulnify?color=3D6DFF" alt="Python versions"></a>
  <a href="https://pypistats.org/packages/vulnify"><img src="https://img.shields.io/pypi/dm/vulnify?color=3D6DFF" alt="Downloads"></a>
  <a href="https://github.com/vulnify/vulnify-sdk-python/blob/main/LICENSE"><img src="https://img.shields.io/pypi/l/vulnify?color=3D6DFF" alt="License: MIT"></a>
  <a href="https://github.com/vulnify/vulnify-sdk-python/actions/workflows/ci.yml"><img src="https://github.com/vulnify/vulnify-sdk-python/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
</p>

<p align="center">
  <a href="https://docs.vulnify.io/sdks/python/"><strong>Docs</strong></a> ·
  <a href="https://app.vulnify.io"><strong>Dashboard</strong></a> ·
  <a href="https://docs.vulnify.io/mcp/"><strong>MCP</strong></a> ·
  <a href="https://github.com/vulnify/vulnify-sdk-python/blob/main/CHANGELOG.md"><strong>Changelog</strong></a>
</p>

---

Vulnify is runtime authorization for AI agents. Before an agent reads, writes, deletes, exports, or emails data, your code sends Vulnify the action metadata (agent, action, resource, destination, record count). Vulnify answers with a decision, a 0 to 100 risk score, and the reasons, and writes the decision to your audit log. Vulnify sees the metadata, not the records.

- **Zero dependencies.** The core package uses only the standard library. Python 3.9+.
- **Fail-closed by default.** If Vulnify cannot be reached, the action is blocked unless you opt into `fail_mode="open"`.
- **Human review built in.** `REVIEW` holds the action until a person approves or denies it.
- **Framework adapters** for LangChain, LangGraph, CrewAI, OpenAI Agents, and MCP, plus webhook verification and a policies-as-code CLI.

## Quickstart

**1. Install**

```bash
pip install vulnify
```

**2. Create an API key** in the [dashboard](https://app.vulnify.io) (a TEST key is fine to start) and export it:

```bash
export VULNIFY_API_KEY="..."
```

**3. Ask before the action runs**

```python
import os
from vulnify import Vulnify

vulnify = Vulnify(api_key=os.environ["VULNIFY_API_KEY"])

decision = vulnify.check(
    agent="SalesBot",
    action="EXPORT_DATA",
    resource="Customer Database",
    destination="EXTERNAL_EMAIL",
    records_affected=12000,
)

outcome = decision.final_decision or decision.decision  # "ALLOW", "REVIEW", or "BLOCK"
if outcome == "ALLOW":
    export_customer_records()
else:
    print(outcome, decision.risk_score, decision.reasons)
```

Or let `guard()` do the branching. The function runs only on `ALLOW`. Anything else raises `VulnifyBlockedError`:

```python
from vulnify import VulnifyBlockedError

try:
    vulnify.guard(
        export_customer_records,
        agent="SalesBot",
        action="EXPORT_DATA",
        resource="Customer Database",
        destination="EXTERNAL_EMAIL",
        records_affected=12000,
    )
except VulnifyBlockedError as err:
    print(err.result.decision, err.result.reasons)
```

`@vulnify.protect(agent=..., action=..., resource=...)` is the same check as a decorator.

## How it works

<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk-python/main/docs/assets/how-it-works.jpg" alt="An AI agent asks Vulnify before acting. ALLOW: it runs. REVIEW: it waits for a person. BLOCK: it never starts." width="100%">
</p>

1. Your agent is about to act. Your code calls `check()` (or `guard()`, or an adapter) with the action metadata.
2. Vulnify evaluates your policies and the risk engine and returns a decision:
   - **`ALLOW`**: run the action.
   - **`REVIEW`**: do not run it yet. A person approves or denies it. Poll with `wait_for_review(event_id)`, or pass `wait={"timeout": 300}` to `guard()`.
   - **`BLOCK`**: do not run it.
3. Every decision lands in the audit log with its score and reasons.

Each decision has a detail view in the dashboard that explains it:

<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk-python/main/docs/assets/block-detail.jpg" alt="Vulnify dashboard: a SalesBot export of 12,000 customer records to an external email, blocked with risk score 100" width="100%">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk-python/main/docs/assets/allow-detail.jpg" alt="Vulnify dashboard: a SupportBot read of one internal record, allowed with risk score 30" width="100%">
</p>

### Which field is authoritative

| Field | Meaning |
| --- | --- |
| `final_decision` | The authoritative result. `REVIEW` while a review is pending, `ALLOW` after approval, `BLOCK` after denial or expiry. Can be `None` on replays of decisions made before the field shipped; then use `decision`. |
| `decision` | The outcome stored on the event. It does not change when a review is resolved. |
| `evaluated_decision` | What full enforcement would decide. Differs from `decision` in monitor mode. |
| `monitored` | `True` when the agent runs in monitor mode (recorded, not enforced). |
| `risk_score` / `risk_level` | Integer 0 to 100, and its level. |
| `reasons` | Why Vulnify decided this. |
| `policy` | The policy that matched, if any. |
| `dlp_findings` / `lgpd_categories` | Sensitive-data findings from optional `content`. The content is scanned and not stored. |
| `review` | Review state; `review["status"]` is `PENDING`, `APPROVED`, `DENIED`, or `EXPIRED`. |
| `degraded` | `True` when Vulnify was unreachable and `fail_mode` decided. |
| `quota_exceeded` / `sandbox` | Plan quota flag, and whether this was a TEST-key sandbox event. |

### Monitor mode

Roll out without blocking anything: in monitor mode the action is allowed and recorded, and the dashboard shows what enforcement would have done.

<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk-python/main/docs/assets/monitor-detail.jpg" alt="Vulnify dashboard in monitor mode: an export that was allowed and recorded, and would have been blocked with enforcement on" width="100%">
</p>

### Audit log

Every decision, including human reviews, is appended to a per-organization SHA-256 hash chain that you can verify from the dashboard. Evidence and audit exports are a JSON or CSV download that includes a SHA-256 checksum. Settings has "SIEM export: JSON or CEF lines". See [Audit log](https://docs.vulnify.io/concepts/audit-log/).

<p align="center">
  <img src="https://raw.githubusercontent.com/vulnify/vulnify-sdk-python/main/docs/assets/audit-logs.jpg" alt="Vulnify audit log listing decisions by agent, action, resource, destination, risk, and decision" width="100%">
</p>

## Configuration

```python
Vulnify(
    api_key="...",          # required
    base_url=None,          # defaults to VULNIFY_BASE_URL, then https://api.vulnify.io
    timeout=3.0,            # seconds per HTTP request
    fail_mode="closed",     # "closed" blocks when Vulnify is unreachable; "open" allows
    retries=2,              # retries after the first attempt, for transient failures only
)
```

| Option | Default | Description |
| --- | --- | --- |
| `api_key` | (required) | Your Vulnify API key. The client does not read it from the environment; pass `os.environ["VULNIFY_API_KEY"]`. |
| `base_url` | `VULNIFY_BASE_URL`, else `https://api.vulnify.io` | API host. An explicit `base_url` wins over the environment variable. Local API: `http://localhost:3000`. |
| `timeout` | `3.0` | Timeout in seconds for each HTTP request. |
| `fail_mode` | `"closed"` | What `check()` returns after retries when Vulnify is unreachable (network error, timeout, `408`, `429`, `5xx`): `"closed"` returns `BLOCK` with `degraded=True`, `"open"` returns `ALLOW` with `degraded=True`. |
| `retries` | `2` | Extra attempts for network errors, `408`, `429`, and `5xx`, with a short backoff. `check()` reuses the same `Idempotency-Key`, so a retry never creates a second event. |

Any other HTTP 4xx (bad key, unknown agent or resource, invalid or oversized payload) raises `VulnifyError` immediately. It is not retried, and `fail_mode="open"` never turns it into an `ALLOW`.

| Environment variable | Used by | Description |
| --- | --- | --- |
| `VULNIFY_BASE_URL` | client, CLI | API host when `base_url` / `--base-url` is not given. |
| `VULNIFY_API_KEY` | CLI | API key; takes precedence over the stored CLI credentials. In your own code, pass it to `Vulnify(api_key=...)`. |

### `check()` arguments

| Argument | Description |
| --- | --- |
| `action` | `READ_DATA`, `WRITE_DATA`, `DELETE_DATA`, `EXPORT_DATA`, or `SEND_EMAIL`. Required. |
| `agent` / `agent_id` | Agent name as registered in Vulnify, or its id. One is required unless the API key is bound to an agent. |
| `resource` / `resource_id` | Resource name as registered in Vulnify, or its id. One is required. |
| `destination` | `INTERNAL`, `EXTERNAL_EMAIL`, or `EXTERNAL_API`. |
| `records_affected` | Number of records the action touches. |
| `content` | Optional text scanned for sensitive data. Scanned in memory and not stored. |
| `idempotency_key` | Optional. Defaults to a fresh UUID per call. |

Other methods: `get_event(event_id)` reads one decision, and `wait_for_review(event_id, timeout=300.0, poll=2.0)` returns `ALLOW`, `BLOCK`, or `TIMEOUT` (or `APPROVED`, `DENIED`, `EXPIRED` for older decisions without `final_decision`).

## Framework integrations

`vulnify.adapters` wraps your tools so they run only on `ALLOW`. Adapters are duck-typed and import a framework only when they need one of its types, so the core install stays dependency-free. Each adapter takes a `describe` callback that turns the tool's arguments into `check()` keywords:

```python
def describe_export(args):
    return {
        "agent": "SalesBot",
        "action": "EXPORT_DATA",
        "resource": "Customer Database",
        "records_affected": args.get("rows"),
    }
```

| Framework | Install | Adapter |
| --- | --- | --- |
| LangChain | `pip install "vulnify[langchain]"` | `guard_langchain_tool(vulnify, tool, describe)` |
| LangGraph | `pip install langgraph` | `langgraph_tool_guard(vulnify, {"tool_name": describe})`, async: `alanggraph_tool_guard` |
| OpenAI Agents | `pip install "vulnify[openai-agents]"` | `guard_openai_agents_tool(vulnify, tool, describe)` |
| MCP server | `pip install "vulnify[mcp]"` | `guard_mcp_handler(vulnify, describe, handler)` |
| MCP client | `pip install "vulnify[mcp]"` | `guard_mcp_client(vulnify, session, {"tool_name": describe})` |
| CrewAI | `pip install crewai` | `guard_crewai_tool(vulnify, tool, describe)`, hook: `crewai_before_tool_call` |

The framework extras require Python 3.10+. A blocked tool answers the agent with Vulnify's reasons instead of running; pass `on_blocked="raise"` to the tool wrappers (LangChain, OpenAI Agents, CrewAI) to raise `VulnifyBlockedError` instead. MCP adapters return an MCP error result. All adapters accept `wait={"timeout": 300}` to wait for a human review. Runnable samples are in [`examples/`](https://github.com/vulnify/vulnify-sdk-python/tree/main/examples).

### LangChain

```python
from langchain_core.tools import tool
from vulnify.adapters import guard_langchain_tool

@tool
def export_customers(rows: int) -> str:
    """Export customer records."""
    return f"exported {rows}"

export_customers = guard_langchain_tool(vulnify, export_customers, describe_export)
export_customers.invoke({"rows": 3})
```

### LangGraph

```python
from langgraph.prebuilt import ToolNode
from vulnify.adapters import langgraph_tool_guard

node = ToolNode(tools, wrap_tool_call=langgraph_tool_guard(vulnify, {"export_customers": describe_export}))
```

A call that is not allowed returns an error `ToolMessage` with the reasons, so the model sees why. Tools not in the map run unchanged.

### OpenAI Agents

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

```python
from vulnify.adapters import guard_mcp_client, guard_mcp_handler

# Inside your MCP server: register the wrapped function.
async def export_customers(rows: int) -> str:
    """Export customer records."""
    return f"exported {rows}"

server.tool()(guard_mcp_handler(vulnify, describe_export, export_customers))

# In an MCP client: check listed tools before the request is sent.
session = guard_mcp_client(vulnify, session, {"export_customers": describe_export})
```

## Webhooks

Vulnify can POST decision, anomaly, and test deliveries to an endpoint you register. Each delivery is signed with HMAC-SHA256 in the `X-Vulnify-Signature` header (`t=<unix seconds>,v1=<hex>`), keyed with your `whsec_` endpoint secret. Verify and parse it with one call, passing the **raw** request body:

```python
from flask import Flask, request
from vulnify import WebhookVerificationError, construct_webhook_from_request

app = Flask(__name__)

@app.post("/webhooks/vulnify")
def vulnify_webhook():
    try:
        event = construct_webhook_from_request(SECRET, request.headers, request.get_data())
    except WebhookVerificationError:
        return "", 400
    # event.id is the delivery id (dedupe retries on it); event.event_id is the event.
    if event.type == "BLOCK":
        print("blocked", event.event_id, event.data.final_decision)
    return "", 204
```

| Function | What it does |
| --- | --- |
| `construct_webhook_from_request(secret, headers, raw_body)` | Reads the signature header (case-insensitive), verifies, and parses. |
| `construct_webhook(secret, signature_header, raw_body)` | Verifies, then parses. |
| `verify_webhook_signature(secret, signature_header, raw_body)` | Verifies only. Raises `WebhookVerificationError`. Default tolerance is 300 seconds. |
| `parse_webhook(raw_body)` | Parses only, into `DecisionWebhook`, `AnomalyWebhook`, or `TestWebhook`. |

Read the raw body with `request.get_data()` (Flask), `await request.body()` (FastAPI), or `request.body` (Django). Do not re-serialize parsed JSON. Samples: [Flask](https://github.com/vulnify/vulnify-sdk-python/blob/main/examples/flask_webhook.py), [FastAPI](https://github.com/vulnify/vulnify-sdk-python/blob/main/examples/fastapi_webhook.py), [Django](https://github.com/vulnify/vulnify-sdk-python/blob/main/examples/django_webhook.py). Delivery format: [Webhook deliveries](https://docs.vulnify.io/api/webhooks/).

## CLI

Policies as code and one-off decisions from the terminal. Same commands as the npm CLI.

```bash
pip install "vulnify[cli]"

vulnify init                      # writes vulnify/policies/example.yaml and a test file
vulnify login --api-key "$VULNIFY_API_KEY"
vulnify check --agent SalesBot --action EXPORT_DATA --resource "Customer Database" --records 12000
vulnify policies validate         # offline schema check with file:line errors
vulnify policies pull --out vulnify/policies
vulnify policies apply --dry-run
vulnify test --local
```

Every command accepts `--json`. There is no telemetry. Credentials are stored in `~/.config/vulnify/credentials.json` (mode 0600); `VULNIFY_API_KEY` and `VULNIFY_BASE_URL` take precedence.

| Exit code | Meaning |
| --- | --- |
| `0` | Success, or `ALLOW` from `check` |
| `1` | Validation error, test failure, or another failure |
| `2` | `REVIEW` from `check` |
| `3` | `BLOCK` from `check` |
| `4` | This server has no policies-as-code API yet |
| `5` | Authentication error |

Policy file format: [Policy files](https://docs.vulnify.io/cli/policy-files/). CLI reference: [CLI](https://docs.vulnify.io/cli/).

## Vulnify MCP server

The [Vulnify MCP server](https://docs.vulnify.io/mcp/) gives AI assistants and IDEs tools to check an action, read a decision, and test policies. Cursor, Claude, Grok, or your own code connect to it. It does not run your agent's tools, and it does not sit between the agent and another MCP server.

The recommended path is **Sign in with Vulnify** (OAuth 2.1). The hosted server is `https://mcp.vulnify.io/mcp`. Add that URL in the client and leave the API-key and OAuth client fields empty. It speaks Streamable HTTP and keeps no session. After you allow access, the server offers five tools: `decide_action`, `get_decision`, `list_policies`, `check_action`, and `test_policies`. It has no approve tool and no deny tool. A person resolves a `REVIEW` in Vulnify.

Use an API key when you need `plan_policy_changes` or `check_mcp_tool_call`, when the client cannot open a browser, or when the key has an IP allowlist. The local process is `@vulnify/mcp` 0.1.2. It needs Node.js 20 or newer, reads `VULNIFY_API_KEY`, and does not open the OAuth consent page:

```bash
npx -y @vulnify/mcp
```

On the hosted server, send the same key on every request as `Authorization: Bearer <api key>` or `X-Vulnify-Key: <api key>`. An API-key session lists all seven tools.

This is different from two other MCP features:

- The **MCP gateway** (`POST /v1/gateway/mcp` on the API) decides an agent's MCP tool call and, when the decision allows it, forwards the call to a registered upstream MCP server. See [MCP gateway](https://docs.vulnify.io/api/gateway-mcp/).
- The **MCP adapters** in this SDK (`guard_mcp_handler`, `guard_mcp_client`) guard tools inside your own MCP server or client. See [MCP](#mcp) above.

## Plans and pricing

The SDK is MIT-licensed. Usage limits, retention, and features depend on your Vulnify plan. See [vulnify.io/pricing](https://vulnify.io/pricing).

## Support

- Docs: [docs.vulnify.io](https://docs.vulnify.io)
- Bugs and feature requests: [GitHub issues](https://github.com/vulnify/vulnify-sdk-python/issues)
- Product support and billing: [hello@vulnify.io](mailto:hello@vulnify.io) ([Support](https://docs.vulnify.io/support/))

## Security

Report vulnerabilities to [security@vulnify.io](mailto:security@vulnify.io). See the [disclosure policy](https://www.vulnify.io/disclosure).

## Development

```bash
pip install -e ".[dev,cli]"
pytest
```

## License

[MIT](https://github.com/vulnify/vulnify-sdk-python/blob/main/LICENSE). Copyright 2026 Vulnify.
