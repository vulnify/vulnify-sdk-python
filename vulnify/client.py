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
    """Configuration or request error (bad API key, unknown agent, invalid or oversized payload).

    Raised for non-retryable HTTP 4xx, including 413. Never silenced by fail_mode.
    Also raised when get_event or wait_for_review exhaust retries on a transient failure.
    """


class VulnifyBlockedError(Exception):
    """The action was blocked, or needs a human review that was not approved."""

    def __init__(self, result: "Decision") -> None:
        reasons = "; ".join(result.reasons) or "no reason given"
        super().__init__(f"Vulnify {result.decision}: {reasons}")
        self.result = result


@dataclass
class Decision:
    """A decision from check() or get_event(). POST and GET return the same body.

    ``decision`` is the outcome stored on the event (``ALLOW``, ``REVIEW``, or ``BLOCK``).
    It does not change when a human resolves a review.

    ``final_decision`` is the outcome to obey. It matches ``decision`` when there is no
    review. While a review is pending it is ``REVIEW``. Approval sets it to ``ALLOW``.
    Denial or expiry sets it to ``BLOCK``. Idempotent replays of decisions made before
    that field shipped may omit it; then it is ``None``, and a review is approved only
    when ``review["status"]`` is ``APPROVED``.

    ``evaluated_decision`` is what full enforcement would have decided. In monitor mode
    it can differ from ``decision``. ``quota_exceeded`` and ``sandbox`` come back on
    both POST and GET.
    """

    id: Optional[str]
    decision: str  # Stored outcome. Does not change when a review is resolved.
    final_decision: Optional[str] = None  # Effective outcome. None when the API omitted it.
    evaluated_decision: str = "ALLOW"  # what would happen with full enforcement (differs in monitor mode)
    monitored: bool = False
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    reasons: List[str] = field(default_factory=list)
    policy: Optional[Dict[str, str]] = None
    dlp_findings: List[str] = field(default_factory=list)
    lgpd_categories: List[str] = field(default_factory=list)
    review: Optional[Dict[str, Any]] = None  # status PENDING | APPROVED | DENIED | EXPIRED
    quota_exceeded: bool = False
    sandbox: bool = False
    degraded: bool = False  # True when Vulnify was unreachable and fail_mode was applied

    @classmethod
    def from_api(cls, body: Dict[str, Any]) -> "Decision":
        return cls(
            id=body.get("id"),
            decision=body["decision"],
            final_decision=body.get("finalDecision"),
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

    def review_outcome(self) -> Optional[str]:
        """Terminal review signal, or None while the review is still pending.

        When ``final_decision`` is present, ``ALLOW`` and ``BLOCK`` are terminal and
        ``REVIEW`` means keep waiting. When it was omitted, ``APPROVED``, ``DENIED``,
        and ``EXPIRED`` from ``review["status"]`` are terminal.
        """
        if self.final_decision is not None:
            if self.final_decision == "REVIEW":
                return None
            return self.final_decision
        status = (self.review or {}).get("status", "PENDING")
        if status in (None, "PENDING"):
            return None
        return status


class Vulnify:
    """Client for the Vulnify ingestion API.

    base_url defaults to https://api.vulnify.io. Pass base_url to point at another host.
    When base_url is omitted, VULNIFY_BASE_URL is used if it is set. An explicit base_url
    wins over the environment variable. For a local API use http://localhost:3000.

    fail_mode: 'closed' (default) blocks when Vulnify is unreachable; 'open' allows.
    It applies only to check(), and only after retries of a network error, 408, 429, or 5xx.
    Non-retryable 4xx (400, 401, 403, 404, 413, and any other 4xx except 408 and 429)
    raise VulnifyError immediately, including when fail_mode is 'open'.
    retries: those transient failures are retried with the same Idempotency-Key on check()
    (a retry never creates a second event), with a short backoff between attempts.
    get_event() uses the same retries and then raises VulnifyError. It does not use fail_mode.
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
            # 408 and 429 are transient. Every other 4xx is the caller's request, including
            # 413 (body over the API's 200kb limit): retrying it cannot succeed, and fail_mode
            # must not turn it into an ALLOW.
            if 400 <= err.code < 500 and err.code not in (408, 429):
                raise VulnifyError(f"Vulnify request rejected ({err.code}): {_error_text(payload)}") from None
            raise _Transient(f"Vulnify responded {err.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise _Transient(str(err)) from None

    def _with_retries(self, method: str, path: str, body: Optional[dict] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        """Retry network errors, 408, 429, and 5xx. Client errors propagate immediately."""
        last: BaseException = _Transient("network error")
        for attempt in range(self.retries + 1):
            try:
                return self._request(method, path, body, idempotency_key)
            except _Transient as err:
                last = err
                if attempt < self.retries:
                    time.sleep(_retry_delay(attempt))
        raise last

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
        """Ask for a decision. Transient failures never raise: see fail_mode.

        A non-retryable 4xx, including 413, raises VulnifyError instead.
        """
        payload = {
            "agent": agent, "agentId": agent_id, "action": action, "resource": resource, "resourceId": resource_id,
            "destination": destination, "recordsAffected": records_affected, "content": content,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        key = idempotency_key or str(uuid.uuid4())
        try:
            return Decision.from_api(self._with_retries("POST", "/v1/events", payload, key))
        except _Transient as err:
            return self._fallback(str(err))

    def get_event(self, event_id: str) -> Decision:
        """Read one event. The body matches check(), including final_decision.

        Retries transient failures the same way as check(). When retries are exhausted,
        raises VulnifyError. Does not apply fail_mode. After a review, obey
        ``final_decision`` (ALLOW, BLOCK, or still REVIEW).
        """
        try:
            body = self._with_retries("GET", f"/v1/events/{event_id}")
        except _Transient as err:
            raise VulnifyError(f"Vulnify unavailable ({err})") from None
        return Decision.from_api(body)

    def wait_for_review(self, event_id: str, timeout: float = 300.0, poll: float = 2.0) -> str:
        """Poll until the review has an effective outcome, or return ``TIMEOUT``.

        When the API sends ``final_decision``, that field wins: ``ALLOW`` means the
        action may run, ``BLOCK`` means it must not, and ``REVIEW`` keeps polling.
        When ``final_decision`` is missing, polling stops on review status
        ``APPROVED``, ``DENIED``, or ``EXPIRED``. A transient failure raises
        VulnifyError after the same retries as check().
        """
        deadline = time.monotonic() + timeout
        while True:
            outcome = self.get_event(event_id).review_outcome()
            if outcome is not None:
                return outcome
            if time.monotonic() + poll > deadline:
                return "TIMEOUT"
            time.sleep(poll)

    def guard(self, fn: Callable[[], T], wait: Optional[dict] = None, **action: Any) -> T:
        """Run fn only if the effective decision is ALLOW.

        ``final_decision`` is that outcome when the API sent it; otherwise ``decision``
        is. BLOCK raises. REVIEW raises unless ``wait={'timeout': 300}`` and the review
        then resolves to ``final_decision`` ALLOW, or to review status APPROVED when
        ``final_decision`` was omitted.
        """
        result = self.check(**action)
        effective = result.final_decision if result.final_decision is not None else result.decision
        if effective == "ALLOW":
            return fn()
        if effective == "REVIEW" and wait is not None and result.id:
            outcome = self.wait_for_review(result.id, **wait)
            if outcome in ("ALLOW", "APPROVED"):
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
    """Network problem, 408, 429, or 5xx. Retried, then handled by the caller. Not part of the public API."""


def _retry_delay(attempt: int) -> float:
    """Seconds to wait after failed attempt ``attempt`` (0-based) before trying again."""
    return min(0.05 * (2 ** attempt), 0.5)


def _error_text(payload: str) -> str:
    """Turn an error body into one line. Validation ``message`` arrays are joined, not repr'd."""
    try:
        message = json.loads(payload).get("message", payload)
    except ValueError:
        return payload
    if isinstance(message, list):
        return "; ".join(str(item) for item in message)
    if message is None:
        return payload
    return str(message)
