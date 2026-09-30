# Changelog

## 0.1.0

Initial standalone release of the `vulnify` Python package.

- Ask Vulnify for a runtime decision before an AI agent action runs: `ALLOW`, `REVIEW`, or `BLOCK`.
- Fail closed by default when Vulnify cannot be reached.
- Optional content is scanned for sensitive data and is not stored.
- `base_url` defaults to `http://localhost:3000`. The production API is `https://api.vulnify.io`.
