# vulnify

Runtime authorization for AI agents. Before the agent exports or sends customer records, your app asks Vulnify. The decision is `ALLOW`, `REVIEW`, or `BLOCK`. The score is an integer from 0 to 100 and comes back with reasons.

Vulnify sees action metadata — agent, action, resource, destination, and record count — not the records. In monitor mode the event is stored and not enforced: obey `final_decision` when it is present, otherwise `decision`. `evaluated_decision` is what enforcement would have returned, and `monitored` is `True`. If Vulnify cannot be reached, the default is fail-closed.

Standard library only. Python 3.9+.

Production API: https://api.vulnify.io

Documentation: https://docs.vulnify.io

## Install

```bash
pip install vulnify
```

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

`vulnify.adapters` guards CrewAI and LangGraph tools without importing either framework. Samples are in `examples/`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT. Copyright 2026 Vulnify.
