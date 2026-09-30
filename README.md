# vulnify

Runtime authorization for AI agents. Ask Vulnify whether an action is allowed before the agent runs it. Standard library only, Python 3.9+.

A check returns one of three decisions:

- `ALLOW` — the action may run.
- `REVIEW` — a person must approve it. `guard()` does not run the action unless you pass `wait` and the review is approved.
- `BLOCK` — the action must not run.

The default is fail-closed (`fail_mode="closed"`). If Vulnify cannot be reached, the SDK returns `BLOCK` and sets `degraded` to `True`. Pass `fail_mode="open"` to allow the action in that case. `Decision.degraded` tells you when the fallback was used. Configuration errors (invalid API key, unknown agent or resource, invalid payload) always raise `VulnifyError`.

Optional `content` is scanned for sensitive data. The content is not stored. Matches come back as `dlp_findings`.

`base_url` defaults to `http://localhost:3000`. The production API is `https://api.vulnify.io`.

This package is not published to PyPI yet. Install it from this repository.

## Install

```bash
pip install "git+https://github.com/vulnify/vulnify-sdk-python.git"
```

## Usage

```python
import os
from vulnify import Vulnify, VulnifyBlockedError

vulnify = Vulnify(api_key=os.environ["VULNIFY_API_KEY"], base_url="https://api.vulnify.io")

# Runs export_customers() only if Vulnify says ALLOW. BLOCK raises VulnifyBlockedError.
# With wait={"timeout": 300}, a REVIEW decision waits for a person and runs only if approved.
vulnify.guard(
    export_customers,
    agent="SalesBot", action="EXPORT_DATA", resource="Customer Database",
    destination="EXTERNAL_EMAIL", records_affected=12000,
    wait={"timeout": 300},
)

@vulnify.protect(agent="SalesBot", action="EXPORT_DATA", resource="Customer Database")
def export_customers():
    ...

d = vulnify.check(agent="SalesBot", action="READ_DATA", resource="Customer Emails", content=email_body)
print(d.decision, d.risk_score, d.reasons, d.dlp_findings)  # content is scanned, never stored
```

Network errors are retried with the same `Idempotency-Key`, so a retry does not create a duplicate event.

## CrewAI and LangGraph

`vulnify.adapters` guards agent tools without importing either framework. Examples are in `examples/`.

```python
from vulnify.adapters import guard_crewai_tool, crewai_before_tool_call, langgraph_tool_guard, alanggraph_tool_guard

def describe_export(args):
    return {"agent": "SalesBot", "action": "EXPORT_DATA", "resource": "Customer Database", "records_affected": args["rows"]}

export_tool = guard_crewai_tool(vulnify, ExportCustomers(), describe_export)
hook = crewai_before_tool_call(vulnify, {"export_customers": describe_export})
node = ToolNode(tools, wrap_tool_call=langgraph_tool_guard(vulnify, {"export_customers": describe_export}))
```

A blocked call does not run the tool. The CrewAI tool answers the reason to the agent (`on_blocked="raise"` raises instead), the hook returns `False`, and LangGraph gets an error `ToolMessage`. Pass `wait={"timeout": 120}` to wait for a person on `REVIEW`. Tools missing from the mapping run unchanged.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT. Copyright 2026 Vulnify.
