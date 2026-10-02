"""Vulnify Python SDK: ask Vulnify whether an AI agent action is allowed before running it.

Standard library only (urllib), Python 3.9+.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TypeVar

T = TypeVar("T")

# Public API. Override with the base_url argument or VULNIFY_BASE_URL (local: http://localhost:3000).
DEFAULT_BASE_URL = "https://api.vulnify.io"


class VulnifyError(Exception):
    """Configuration or request error (bad API key, unknown agent, invalid payload). Never silenced by fail_mode."""


class VulnifyBlockedError(Exception):
    """The action was blocked, or needs a human review that was not approved."""

    def __init__(self, result: "Decision") -> None:
        reasons = "; ".join(result.reasons) or "no reason given"
        super().__init__(f"Vulnify {result.decision}: {reasons}")
        self.result = result


@dataclass
class Decision:
    id: Optional[str]
    decision: str  # ALLOW | REVIEW | BLOCK: what you must obey
    evaluated_decision: str = "ALLOW"  # what would happen with full enforcement (differs in monitor mode)
    monitored: bool = False
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    reasons: List[str] = field(default_factory=list)
    policy: Optional[Dict[str, str]] = None
    dlp_findings: List[str] = field(default_factory=list)
    lgpd_categories: List[str] = field(default_factory=list)
    review: Optional[Dict[str, Any]] = None
    quota_exceeded: bool = False
    sandbox: bool = False
    degraded: bool = False  # True when Vulnify was unreachable and fail_mode was applied

    @classmethod
    def from_api(cls, body: Dict[str, Any]) -> "Decision":
        return cls(
            id=body.get("id"),
            decision=body["decision"],
            evaluated_decision=body.get("evaluatedDecision", body["decision"]),
            monitored=bool(body.get("monitored", False)),
            risk_level=body.get("riskLevel"),
            risk_score=body.get("riskScore"),
            reasons=list(body.get("reasons", [])),
            policy=body.get("policy"),
            dlp_findings=list(body.get("dlpFindings", [])),
            lgpd_categories=list(body.get("lgpdCategories", [])),
            review=body.get("review"),
            quota_exceeded=bool(body.get("quotaExceeded", False)),
            sandbox=bool(body.get("sandbox", False)),
        )


class Vulnify:
    """Client for the Vulnify ingestion API.

    base_url defaults to https://api.vulnify.io. Pass base_url to point at another host.
    When base_url is omitted, VULNIFY_BASE_URL is used if it is set. An explicit base_url
    wins over the environment variable. For a local API use http://localhost:3000.

    fail_mode: 'closed' (default) blocks when Vulnify is unreachable; 'open' allows.
    retries: network retries reusing the same Idempotency-Key (never creates duplicate events).
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        timeout: float = 3.0,
        fail_mode: str = "closed",
        retries: int = 2,
    ) -> None:
        if not api_key:
            raise ValueError("Vulnify: api_key is required")
        if fail_mode not in ("open", "closed"):
            raise ValueError("fail_mode must be 'open' or 'closed'")
        if base_url is None:
            base_url = os.environ.get("VULNIFY_BASE_URL", "").strip() or DEFAULT_BASE_URL
        else:
            base_url = base_url.strip()
            if not base_url:
                raise ValueError("Vulnify: base_url is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.fail_mode = fail_mode
        self.retries = retries

    # ------------------------------------------------------------------ HTTP
    def _request(self, method: str, path: str, body: Optional[dict] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                return json.loads(res.read().decode() or "{}")
        except urllib.error.HTTPError as err:
            payload = err.read().decode()
            if err.code in (400, 401, 403, 404):
                try:
                    message = json.loads(payload).get("message", payload)
                except ValueError:
                    message = payload
                raise VulnifyError(f"Vulnify request rejected ({err.code}): {message}") from None
            raise _Transient(f"Vulnify responded {err.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise _Transient(str(err)) from None

    # ------------------------------------------------------------------ API
    def check(
        self,
        agent: Optional[str] = None,
        action: str = "",
        resource: Optional[str] = None,
        destination: Optional[str] = None,
        records_affected: Optional[int] = None,
        content: Optional[str] = None,
        agent_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Decision:
        """Ask for a decision. Network problems never raise: see fail_mode."""
        payload = {
            "agent": agent, "agentId": agent_id, "action": action, "resource": resource, "resourceId": resource_id,
            "destination": destination, "recordsAffected": records_affected, "content": content,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        key = idempotency_key or str(uuid.uuid4())
        last = "network error"
        for _ in range(self.retries + 1):
            try:
                return Decision.from_api(self._request("POST", "/v1/events", payload, key))
            except _Transient as err:
                last = str(err)
        return self._fallback(last)

    def get_event(self, event_id: str) -> Decision:
        return Decision.from_api(self._request("GET", f"/v1/events/{event_id}"))

    def wait_for_review(self, event_id: str, timeout: float = 300.0, poll: float = 2.0) -> str:
        """Polls until APPROVED, DENIED or EXPIRED; returns 'TIMEOUT' if nobody answers in time."""
        deadline = time.monotonic() + timeout
        while True:
            review = self.get_event(event_id).review or {}
            status = review.get("status", "PENDING")
            if status != "PENDING":
                return status
            if time.monotonic() + poll > deadline:
                return "TIMEOUT"
            time.sleep(poll)

    def guard(self, fn: Callable[[], T], wait: Optional[dict] = None, **action: Any) -> T:
        """Run fn only if allowed. BLOCK raises; REVIEW raises unless `wait={'timeout': 300}` and it is approved."""
        result = self.check(**action)
        if result.decision == "ALLOW":
            return fn()
        if result.decision == "REVIEW" and wait is not None and result.id:
            outcome = self.wait_for_review(result.id, **wait)
            if outcome == "APPROVED":
                return fn()
            result.reasons.append(f"Review {outcome.lower()}")
        raise VulnifyBlockedError(result)

    def _fallback(self, reason: str) -> Decision:
        allow = self.fail_mode == "open"
        d = "ALLOW" if allow else "BLOCK"
        return Decision(
            id=None, decision=d, evaluated_decision=d, degraded=True,
            reasons=[f"Vulnify unavailable ({reason}); fail_mode={self.fail_mode}"],
        )

    def protect(self, **action: Any) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator: @vulnify.protect(agent='SalesBot', action='EXPORT_DATA', resource='Customer Database')"""

        def decorator(fn: Callable[..., T]) -> Callable[..., T]:
            def wrapper(*args: Any, **kwargs: Any) -> T:
                return self.guard(lambda: fn(*args, **kwargs), **action)

            wrapper.__name__ = getattr(fn, "__name__", "protected")
            return wrapper

        return decorator


class _Transient(Exception):
    """Network problem or 5xx: retried, then handled by fail_mode."""
