# Changelog

## 0.4.0

- `vulnify` console script, installed with `pip install "vulnify[cli]"` (PyYAML and jsonschema). The core install still has no required dependencies. Python 3.9+.
- Commands match the npm CLI: `init`, `login`, `check`, `policies validate`, `policies pull`, `policies apply`, and `test`. Every command accepts `--json`.
- Credentials are stored in `~/.config/vulnify/credentials.json` with mode 0600. `VULNIFY_API_KEY` and `VULNIFY_BASE_URL` take precedence over that file.
- Exit codes: 0 ok or ALLOW, 1 failure, 2 REVIEW, 3 BLOCK, 4 the server has no policies-as-code API, 5 authentication error.
- `policies pull`, `policies apply`, and `test` print `This Vulnify server does not support policies as code yet` and exit 4 when the server returns 404.
- Policy YAML is checked against `vulnify/schema/policies.v1.json`, a byte-identical copy of `schema/policies.v1.json` on `vulnify-sdk` main. CI fetches that file and fails if the bytes differ.
- `spec.action` is the action family (`EXPORT`, not `EXPORT_DATA`). Conditions use `minRecords` (`recordsAffected >= n`; more than 1000 records is `minRecords: 1001`) and `allOf` / `anyOf`.
- `init` also writes `vulnify/.gitignore`. `check` follows `finalDecision`. `login` probes `GET /v1/events/00000000-0000-4000-8000-000000000000` and treats HTTP 403 as a successful probe. `policies pull` keeps `id` and `updatedAt`. `test --local` loads policies from `vulnify/policies`.

## 0.3.1

- `parse_webhook` accepts a TEST `eventId` that starts with `test-`. The value is its own id, not `test-` plus the delivery id.

## 0.3.0

- `guard_langchain_tool` guards a LangChain tool. Install the framework with `vulnify[langchain]`.
- `guard_openai_agents_tool` guards an OpenAI Agents `FunctionTool` (`on_invoke_tool`) or a tool config with `execute`. Install the framework with `vulnify[openai-agents]`.
- `guard_mcp_handler` guards an MCP server tool function, and `guard_mcp_client` guards `ClientSession.call_tool`. A blocked call returns an MCP error result. Install the SDK with `vulnify[mcp]`.
- These adapters call `guard`, so a `REVIEW` follows `final_decision`: `ALLOW` runs the tool and `BLOCK` does not.
- The core package still has no required dependencies. The frameworks are optional extras and are imported only when an adapter needs a type from that package.
- The npm SDK's Vercel AI SDK helper is not ported. There is no Python counterpart.
- `verify_webhook_signature` checks `X-Vulnify-Signature` over the raw body. The key is the `whsec_` secret as UTF-8. A timestamp 300 seconds away is still accepted, and any matching `v1` value is enough. Failure raises `WebhookVerificationError`.
- `parse_webhook` and `construct_webhook` turn a delivery into a decision, anomaly, or test dataclass. Decision payloads include `decision` and `final_decision`, and every delivery includes `event_id`.
- `construct_webhook_from_request` reads the signature header for Flask, FastAPI, and Django. Samples are in `examples/`. The core package still has no required dependencies.

## 0.2.1

- Map optional `final_decision`. It is `REVIEW` while a review is pending, `ALLOW` after approval, and `BLOCK` after denial or expiry. The stored `decision` does not change. Idempotent replays of older decisions may omit `final_decision`.
- `wait_for_review` and `guard(..., wait=)` follow `final_decision` when it is present, and review status `APPROVED` when it is not.
- `GET /v1/events/{id}` returns the same decision body as `check()`, including `quota_exceeded`, `sandbox`, `lgpd_categories`, and `final_decision`.

## 0.2.0

- Default `base_url` is `https://api.vulnify.io`. Override it with the `base_url` argument or with `VULNIFY_BASE_URL` (local API: `http://localhost:3000`). An explicit `base_url` wins over the environment variable.
- Publish metadata for the public package: Homepage `https://docs.vulnify.io`, Source, Issues, classifiers, and keywords. The wheel and sdist include `py.typed`.
- `413` and every other HTTP 4xx except `408` and `429` raise `VulnifyError` immediately. They are not retried and `fail_mode` cannot turn them into an allow. `408`, `429`, and `5xx` stay retryable.
- `get_event` and `wait_for_review` retry transient failures the same way as `check`, then raise `VulnifyError`. They do not apply `fail_mode`.
- A resolved review leaves `decision` as `REVIEW`. The go signal is `review["status"] == "APPROVED"`. `GET /v1/events/{id}` omits `quotaExceeded` and `sandbox`; the SDK does not fill those in.
- Validation `message` arrays are joined into one string. Retries wait a short backoff between attempts.

## 0.1.1

- Document a production export check a caller can copy: `ALLOW` runs the export, `REVIEW` stops and asks for a human, and `BLOCK` or an unreachable API does not run it.

## 0.1.0

Initial standalone release of the `vulnify` Python package. Install with `pip install vulnify`.

- Ask Vulnify for a runtime decision before an AI agent action runs: `ALLOW`, `REVIEW`, or `BLOCK`.
- Fail closed by default when Vulnify cannot be reached.
- Optional content is scanned for sensitive data and is not stored.
- `base_url` defaults to `http://localhost:3000`. The production API is `https://api.vulnify.io`.
