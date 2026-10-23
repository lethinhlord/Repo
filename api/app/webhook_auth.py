from __future__ import annotations

import hashlib
import hmac
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path

import rfc8785

from api.app.contracts import (
    SignedWazuhIngestRequest,
    SignedWazuhIngestResponse,
    WazuhAlert,
)


class WebhookAuthenticationError(ValueError):
    pass


def canonical_payload(payload: dict[str, object]) -> bytes:
    """Return RFC 8785 JCS bytes so Python and JavaScript sign identical JSON."""

    try:
        return rfc8785.dumps(payload)
    except rfc8785.CanonicalizationError as exc:
        raise WebhookAuthenticationError(
            "payload is not RFC 8785/I-JSON canonicalizable"
        ) from exc


def sign_payload(
    secret: str, *, timestamp: int, nonce: str, payload: dict[str, object]
) -> str:
    payload_hash = hashlib.sha256(canonical_payload(payload)).hexdigest()
    message = f"{timestamp}\n{nonce}\n{payload_hash}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class WebhookAuthenticator:
    def __init__(
        self,
        path: Path,
        secret: str,
        *,
        max_skew_seconds: int = 300,
        max_requests_per_minute: int = 300,
    ) -> None:
        if len(secret.encode()) < 32:
            raise ValueError("WAZUH_WEBHOOK_SECRET must contain at least 32 bytes")
        if not 30 <= max_skew_seconds <= 900:
            raise ValueError("max_skew_seconds must be between 30 and 900")
        if not 1 <= max_requests_per_minute <= 10_000:
            raise ValueError("max_requests_per_minute must be between 1 and 10000")
        self.path = path
        self.secret = secret
        self.max_skew_seconds = max_skew_seconds
        self.max_requests_per_minute = max_requests_per_minute
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_nonces (
                    nonce TEXT PRIMARY KEY,
                    seen_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_request_log (
                    accepted_at INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS webhook_request_log_time "
                "ON webhook_request_log (accepted_at)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def verify(self, request: SignedWazuhIngestRequest) -> SignedWazuhIngestResponse:
        now = int(time.time())
        if abs(now - request.timestamp) > self.max_skew_seconds:
            raise WebhookAuthenticationError("signed webhook timestamp is expired")
        expected = sign_payload(
            self.secret,
            timestamp=request.timestamp,
            nonce=request.nonce,
            payload=request.payload,
        )
        if not hmac.compare_digest(expected, request.signature.casefold()):
            raise WebhookAuthenticationError("invalid webhook signature")
        alert = WazuhAlert.model_validate(request.payload)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM webhook_nonces WHERE expires_at < ?", (now,))
            connection.execute(
                "DELETE FROM webhook_request_log WHERE accepted_at <= ?", (now - 60,)
            )
            accepted = connection.execute(
                "SELECT COUNT(*) FROM webhook_request_log"
            ).fetchone()[0]
            if accepted >= self.max_requests_per_minute:
                raise WebhookAuthenticationError("signed webhook rate limit exceeded")
            try:
                connection.execute(
                    "INSERT INTO webhook_nonces VALUES (?, ?, ?)",
                    (request.nonce, now, now + self.max_skew_seconds),
                )
            except sqlite3.IntegrityError as exc:
                raise WebhookAuthenticationError("webhook nonce was already used") from exc
            connection.execute(
                "INSERT INTO webhook_request_log VALUES (?)",
                (now,),
            )
        return SignedWazuhIngestResponse(
            source_event_id=alert.id,
            payload_sha256=hashlib.sha256(canonical_payload(request.payload)).hexdigest(),
            verified_at=datetime.now(UTC),
        )
