from __future__ import annotations

import time
from pathlib import Path

import pytest

from api.app.contracts import SignedWazuhIngestRequest
from api.app.webhook_auth import (
    WebhookAuthenticationError,
    WebhookAuthenticator,
    canonical_payload,
    sign_payload,
)

SECRET = "test-webhook-secret-that-is-at-least-32-bytes"


def payload() -> dict[str, object]:
    return {
        "id": "AUTH-1",
        "timestamp": "2026-10-05T12:00:00Z",
        "rule": {"id": "60100", "level": 7},
        "agent": {"id": "001", "name": "WIN11-TARGET"},
        "decoder": {"name": "windows_eventchannel"},
        "data": {},
    }


def signed_request(*, nonce: str = "nonce-0000000001", offset: int = 0):
    timestamp = int(time.time()) + offset
    body = payload()
    return SignedWazuhIngestRequest(
        timestamp=timestamp,
        nonce=nonce,
        signature=sign_payload(
            SECRET,
            timestamp=timestamp,
            nonce=nonce,
            payload=body,
        ),
        payload=body,
    )


def test_valid_signature_is_accepted_once(tmp_path: Path) -> None:
    authenticator = WebhookAuthenticator(tmp_path / "nonces.sqlite3", SECRET)

    result = authenticator.verify(signed_request())

    assert result.verified is True
    assert result.source_event_id == "AUTH-1"


def test_canonical_payload_survives_javascript_number_round_trip() -> None:
    python_payload = {"value": 12.0, "small": 1e-6, "nested": {"score": 1.0}}
    javascript_round_trip = {"value": 12, "small": 0.000001, "nested": {"score": 1}}

    assert canonical_payload(python_payload) == canonical_payload(javascript_round_trip)
    assert sign_payload(
        SECRET,
        timestamp=1_700_000_000,
        nonce="cross-runtime-nonce",
        payload=python_payload,
    ) == sign_payload(
        SECRET,
        timestamp=1_700_000_000,
        nonce="cross-runtime-nonce",
        payload=javascript_round_trip,
    )


def test_nonce_replay_is_rejected(tmp_path: Path) -> None:
    authenticator = WebhookAuthenticator(tmp_path / "nonces.sqlite3", SECRET)
    request = signed_request()
    authenticator.verify(request)

    with pytest.raises(WebhookAuthenticationError, match="already used"):
        authenticator.verify(request)


def test_tamper_and_expired_timestamp_are_rejected(tmp_path: Path) -> None:
    authenticator = WebhookAuthenticator(tmp_path / "nonces.sqlite3", SECRET)
    tampered = signed_request(nonce="nonce-0000000002")
    tampered.payload["id"] = "TAMPERED"

    with pytest.raises(WebhookAuthenticationError, match="invalid webhook signature"):
        authenticator.verify(tampered)
    with pytest.raises(WebhookAuthenticationError, match="expired"):
        authenticator.verify(signed_request(nonce="nonce-0000000003", offset=-301))


def test_signed_webhook_rate_limit_is_fail_closed(tmp_path: Path) -> None:
    authenticator = WebhookAuthenticator(
        tmp_path / "nonces.sqlite3",
        SECRET,
        max_requests_per_minute=2,
    )
    authenticator.verify(signed_request(nonce="nonce-rate-000001"))
    authenticator.verify(signed_request(nonce="nonce-rate-000002"))

    with pytest.raises(WebhookAuthenticationError, match="rate limit"):
        authenticator.verify(signed_request(nonce="nonce-rate-000003"))
