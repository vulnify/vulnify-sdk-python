# Changelog

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
