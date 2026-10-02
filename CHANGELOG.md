# Changelog

## 0.2.0

- Default `base_url` is `https://api.vulnify.io`. Override it with the `base_url` argument or with `VULNIFY_BASE_URL` (local API: `http://localhost:3000`). An explicit `base_url` wins over the environment variable.
- Publish metadata for the public package: Homepage `https://docs.vulnify.io`, Source, Issues, classifiers, and keywords. The wheel and sdist include `py.typed`.

## 0.1.1

- Document a production export check a caller can copy: `ALLOW` runs the export, `REVIEW` stops and asks for a human, and `BLOCK` or an unreachable API does not run it.

## 0.1.0

Initial standalone release of the `vulnify` Python package. Install with `pip install vulnify`.

- Ask Vulnify for a runtime decision before an AI agent action runs: `ALLOW`, `REVIEW`, or `BLOCK`.
- Fail closed by default when Vulnify cannot be reached.
- Optional content is scanned for sensitive data and is not stored.
- `base_url` defaults to `http://localhost:3000`. The production API is `https://api.vulnify.io`.
