"""Verify Vulnify webhooks.

The signature matches the npm helper ``verifyWebhookSignature``: HMAC-SHA256, keyed by the endpoint
secret as UTF-8 (the whole ``whsec_`` value, not base64-decoded), over ``str(timestamp) + '.' + raw body``.
The header is ``X-Vulnify-Signature: t=<unix seconds>,v1=<hex>``. Several ``v1`` values are accepted so a
rotated secret still verifies. A timestamp exactly ``tolerance_seconds`` away (default 300) is still valid.

This module uses the standard library only. Flask, FastAPI, and Django samples are in ``examples/``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Union

SIGNATURE_HEADER = "X-Vulnify-Signature"
ATTEMPT_HEADER = "X-Vulnify-Attempt"
EVENT_HEADER = "X-Vulnify-Event"
DELIVERY_HEADER = "X-Vulnify-Delivery"

DEFAULT_TOLERANCE_SECONDS = 300

DECISION_TYPES = ("BLOCK", "REVIEW", "CRITICAL")
ANOMALY_TYPE = "ANOMALY"
TEST_TYPE = "TEST"


class WebhookVerificationError(Exception):
    """The webhook signature is missing, malformed, stale, or does not match the secret."""


class WebhookPayloadError(Exception):
    """The body verified, or was parsed on its own, but does not match a Vulnify webhook."""


@dataclass(frozen=True)
class WebhookDecisionData:
    """Decision payload. ``decision`` is stored on the event. ``final_decision`` is the outcome to obey."""

    id: str
    agent: str
    action: str
    resource: str
    risk_score: int
    risk_level: str
    decision: str
    final_decision: str


@dataclass(frozen=True)
class WebhookAnomalyData:
    id: str
    kind: str
    severity: str
    message: str
    agent_id: str
    message_code: str
    message_params: Mapping[str, Any]


@dataclass(frozen=True)
class WebhookTestData:
    message: str
    webhook_id: str
    organization_id: str


@dataclass(frozen=True)
class DecisionWebhook:
    """A ``decision`` delivery. ``id`` is the delivery id (dedupe retries on it). ``event_id`` is the security event."""

    id: str
    type: str
    types: tuple
    event_id: str
    created_at: str
    data: WebhookDecisionData


@dataclass(frozen=True)
class AnomalyWebhook:
    """An ``anomaly`` delivery. ``id`` is the delivery id. ``event_id`` is the anomaly id."""

    id: str
    type: str
    types: tuple
    event_id: str
    created_at: str
    data: WebhookAnomalyData


@dataclass(frozen=True)
class TestWebhook:
    """A ``test`` delivery. ``event_id`` is ``test-`` plus the delivery id. This is not a security decision."""

    id: str
    type: str
    types: tuple
    event_id: str
    created_at: str
    data: WebhookTestData


WebhookEvent = Union[DecisionWebhook, AnomalyWebhook, TestWebhook]


def verify_webhook_signature(
    secret: str,
    signature_header: Optional[str],
    raw_body: Union[bytes, bytearray, str],
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[float] = None,
) -> None:
    """Raise :class:`WebhookVerificationError` unless ``signature_header`` signs ``raw_body``.

    ``raw_body`` must be the exact request bytes. Pass a ``str`` only when it is the UTF-8 text of those
    bytes. ``now`` is unix seconds (``time.time()`` by default), not the npm helper's milliseconds.
    """
    if not isinstance(secret, str) or secret == "":
        raise WebhookVerificationError("Webhook secret must be the non-empty whsec_ endpoint secret")
    if tolerance_seconds < 0:
        raise ValueError("tolerance_seconds must be >= 0")
    if signature_header is None or signature_header == "":
        raise WebhookVerificationError("Missing X-Vulnify-Signature header")

    timestamp, candidates = _parse_signature(signature_header)
    now_seconds = int(time.time() if now is None else now)
    if abs(now_seconds - timestamp) > tolerance_seconds:
        raise WebhookVerificationError("Webhook timestamp is outside the tolerance window")

    expected = _mac(secret, timestamp, _as_bytes(raw_body))
    matched = False
    for candidate in candidates:
        given = _decode_signature(candidate)
        if given is None:
            continue
        matched |= hmac.compare_digest(given, expected)
    if not matched:
        raise WebhookVerificationError("Webhook signature does not match")


def parse_webhook(raw_body: Union[bytes, bytearray, str]) -> WebhookEvent:
    """Parse a raw webhook body into a decision, anomaly, or test event.

    Does not check the signature. Call :func:`verify_webhook_signature` or :func:`construct_webhook` first.
    """
    try:
        payload = json.loads(_as_bytes(raw_body).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebhookPayloadError("Webhook body is not UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise WebhookPayloadError("Webhook body must be a JSON object")

    delivery_id = _string(payload, "id")
    event_type = _string(payload, "type")
    types = _string_tuple(payload, "types")
    event_id = _string(payload, "eventId")
    created_at = _string(payload, "createdAt")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise WebhookPayloadError("Webhook data must be an object")
    if not types or types[0] != event_type:
        raise WebhookPayloadError("Webhook type must be the first entry of types")

    if event_type in DECISION_TYPES:
        parsed = _decision_data(data)
        if event_id != parsed.id:
            raise WebhookPayloadError("Webhook eventId must match data.id")
        return DecisionWebhook(delivery_id, event_type, types, event_id, created_at, parsed)
    if event_type == ANOMALY_TYPE:
        parsed_anomaly = _anomaly_data(data)
        if event_id != parsed_anomaly.id:
            raise WebhookPayloadError("Webhook eventId must match data.id")
        return AnomalyWebhook(delivery_id, event_type, types, event_id, created_at, parsed_anomaly)
    if event_type == TEST_TYPE:
        if event_id != "test-" + delivery_id:
            raise WebhookPayloadError("Test eventId must be test- followed by the delivery id")
        return TestWebhook(delivery_id, event_type, types, event_id, created_at, _test_data(data))
    raise WebhookPayloadError("Unknown webhook type: " + event_type)


def construct_webhook(
    secret: str,
    signature_header: Optional[str],
    raw_body: Union[bytes, bytearray, str],
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[float] = None,
) -> WebhookEvent:
    """Verify the raw body, then parse it."""
    verify_webhook_signature(secret, signature_header, raw_body, tolerance_seconds=tolerance_seconds, now=now)
    return parse_webhook(raw_body)


def construct_webhook_from_request(
    secret: str,
    headers: Mapping[str, Any],
    raw_body: Union[bytes, bytearray, str],
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[float] = None,
) -> WebhookEvent:
    """Verify and parse a framework request. ``headers`` is matched without regard to case.

    Read the body with ``request.get_data()`` (Flask), ``await request.body()`` (FastAPI), or
    ``request.body`` (Django). Do not pass a re-serialized JSON object. Return HTTP 400 when this
    raises :class:`WebhookVerificationError`: a 4xx other than 408 or 429 stops Vulnify's retries.
    """
    return construct_webhook(
        secret,
        header_value(headers, SIGNATURE_HEADER),
        raw_body,
        tolerance_seconds=tolerance_seconds,
        now=now,
    )


def header_value(headers: Optional[Mapping[str, Any]], name: str) -> Optional[str]:
    """Read one header. Flask, FastAPI, Django, and a plain dict all work."""
    if headers is None:
        return None
    direct = None
    getter = getattr(headers, "get", None)
    if callable(getter):
        direct = getter(name)
        if direct is None:
            direct = getter(name.lower())
    if direct is None:
        wanted = name.lower()
        try:
            pairs = list(headers.items())
        except Exception:
            pairs = []
        for key, value in pairs:
            if str(key).lower() == wanted:
                direct = value
                break
    if isinstance(direct, (list, tuple)):
        direct = direct[0] if direct else None
    if direct is None:
        return None
    if isinstance(direct, bytes):
        return direct.decode("latin-1")
    return str(direct)


def _as_bytes(raw_body: Union[bytes, bytearray, str]) -> bytes:
    if isinstance(raw_body, str):
        return raw_body.encode("utf-8")
    if isinstance(raw_body, bytearray):
        return bytes(raw_body)
    if isinstance(raw_body, bytes):
        return raw_body
    raise WebhookVerificationError("Webhook body must be bytes or str")


def _mac(secret: str, timestamp: int, raw_body: bytes) -> bytes:
    message = str(timestamp).encode("ascii") + b"." + raw_body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()


def _parse_signature(signature_header: str) -> tuple:
    if not isinstance(signature_header, str):
        raise WebhookVerificationError("X-Vulnify-Signature must be a string")
    timestamp = None
    candidates = []
    for part in signature_header.split(","):
        piece = part.strip()
        if "=" not in piece:
            continue
        key, value = piece.split("=", 1)
        if key == "t":
            if not value.isdigit():
                raise WebhookVerificationError("X-Vulnify-Signature timestamp is malformed")
            timestamp = int(value)
        elif key == "v1" and value:
            candidates.append(value)
    if timestamp is None or not candidates:
        raise WebhookVerificationError("X-Vulnify-Signature is malformed")
    return timestamp, candidates


def _decode_signature(candidate: str) -> Optional[bytes]:
    if len(candidate) != 64:
        return None
    try:
        given = bytes.fromhex(candidate)
    except ValueError:
        return None
    if len(given) != 32:
        return None
    return given


def _string(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or value == "":
        raise WebhookPayloadError("Webhook field " + key + " must be a string")
    return value


def _string_tuple(payload: Mapping[str, Any], key: str) -> tuple:
    value = payload.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise WebhookPayloadError("Webhook field " + key + " must be a non-empty list of strings")
    return tuple(value)


def _decision_data(data: Mapping[str, Any]) -> WebhookDecisionData:
    score = data.get("riskScore")
    if isinstance(score, bool) or not isinstance(score, int):
        raise WebhookPayloadError("Webhook riskScore must be an integer")
    return WebhookDecisionData(
        id=_string(data, "id"),
        agent=_string(data, "agent"),
        action=_string(data, "action"),
        resource=_string(data, "resource"),
        risk_score=score,
        risk_level=_string(data, "riskLevel"),
        decision=_string(data, "decision"),
        final_decision=_string(data, "finalDecision"),
    )


def _anomaly_data(data: Mapping[str, Any]) -> WebhookAnomalyData:
    params = data.get("messageParams")
    if not isinstance(params, dict):
        raise WebhookPayloadError("Webhook messageParams must be an object")
    for key, value in params.items():
        if not isinstance(key, str) or not _param_value(value):
            raise WebhookPayloadError("Webhook messageParams values must be strings, numbers, or null")
    return WebhookAnomalyData(
        id=_string(data, "id"),
        kind=_string(data, "kind"),
        severity=_string(data, "severity"),
        message=_string(data, "message"),
        agent_id=_string(data, "agentId"),
        message_code=_string(data, "messageCode"),
        message_params=params,
    )


def _param_value(value: Any) -> bool:
    if value is None or isinstance(value, str):
        return True
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return True


def _test_data(data: Mapping[str, Any]) -> WebhookTestData:
    return WebhookTestData(
        message=_string(data, "message"),
        webhook_id=_string(data, "webhookId"),
        organization_id=_string(data, "organizationId"),
    )
