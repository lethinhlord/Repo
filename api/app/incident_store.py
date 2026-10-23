from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from api.app.contracts import (
    IncidentRecordRequest,
    IncidentRecordResponse,
    NotificationDispatchResponse,
)


class IncidentStore:
    """Durable incident and manual-notification outbox with idempotent updates."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    route TEXT NOT NULL,
                    review_required INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS processed_events (
                    source_event_id TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS notification_outbox (
                    incident_id TEXT PRIMARY KEY,
                    notification TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT,
                    channel TEXT,
                    attempted_at TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(notification_outbox)")
            }
            if "delivered_at" not in columns:
                connection.execute(
                    "ALTER TABLE notification_outbox ADD COLUMN delivered_at TEXT"
                )
            if "channel" not in columns:
                connection.execute("ALTER TABLE notification_outbox ADD COLUMN channel TEXT")
            if "attempted_at" not in columns:
                connection.execute(
                    "ALTER TABLE notification_outbox ADD COLUMN attempted_at TEXT"
                )
            if "attempt_count" not in columns:
                connection.execute(
                    "ALTER TABLE notification_outbox ADD COLUMN attempt_count "
                    "INTEGER NOT NULL DEFAULT 0"
                )

    @staticmethod
    def _payload(request: IncidentRecordRequest) -> tuple[str, str]:
        payload = json.dumps(
            request.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        return payload, hashlib.sha256(payload.encode()).hexdigest()

    def record(self, request: IncidentRecordRequest) -> IncidentRecordResponse:
        payload, payload_hash = self._payload(request)
        now = datetime.now(UTC)
        now_text = now.isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            processed = connection.execute(
                "SELECT payload_hash, incident_id FROM processed_events "
                "WHERE source_event_id = ?",
                (request.source_event_id,),
            ).fetchone()
            if processed is not None:
                if processed["payload_hash"] != payload_hash:
                    raise ValueError(
                        "source_event_id was already processed with a different decision"
                    )
                return IncidentRecordResponse(
                    incident_id=processed["incident_id"],
                    source_event_id=request.source_event_id,
                    disposition="duplicate",
                    notification_status="ALREADY_QUEUED",
                    route=request.route,
                    review_required=request.review_required,
                    recorded_at=now,
                )

            existing = connection.execute(
                "SELECT payload_hash FROM incidents WHERE incident_id = ?",
                (request.incident_id,),
            ).fetchone()
            disposition = "created" if existing is None else "updated"
            if existing is None:
                connection.execute(
                    "INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        request.incident_id,
                        payload_hash,
                        payload,
                        request.route,
                        int(request.review_required),
                        now_text,
                        now_text,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE incidents SET payload_hash = ?, payload_json = ?, route = ?,
                      review_required = ?, updated_at = ? WHERE incident_id = ?
                    """,
                    (
                        payload_hash,
                        payload,
                        request.route,
                        int(request.review_required),
                        now_text,
                        request.incident_id,
                    ),
                )
            connection.execute(
                "INSERT INTO processed_events VALUES (?, ?, ?, ?)",
                (request.source_event_id, payload_hash, request.incident_id, now_text),
            )
            queued = connection.execute(
                "INSERT OR IGNORE INTO notification_outbox "
                "(incident_id, notification, status, created_at) "
                "VALUES (?, ?, 'QUEUED', ?)",
                (request.incident_id, request.notification, now_text),
            ).rowcount

        return IncidentRecordResponse(
            incident_id=request.incident_id,
            source_event_id=request.source_event_id,
            disposition=disposition,
            notification_status="QUEUED" if queued else "ALREADY_QUEUED",
            route=request.route,
            review_required=request.review_required,
            recorded_at=now,
        )

    def dispatch_notification(
        self,
        incident_id: str,
        sender: Callable[[str, str], str],
        *,
        lease_seconds: int = 300,
        now: datetime | None = None,
    ) -> NotificationDispatchResponse:
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        attempted_at = now or datetime.now(UTC)
        if attempted_at.tzinfo is None or attempted_at.utcoffset() is None:
            raise ValueError("now must include a timezone")
        attempted_at_text = attempted_at.astimezone(UTC).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT notification, status, delivered_at, channel, attempted_at "
                "FROM notification_outbox WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if row is None:
                raise ValueError("incident notification is not queued")
            if row["status"] == "SENT":
                return NotificationDispatchResponse(
                    incident_id=incident_id,
                    notification_status="ALREADY_SENT",
                    channel=row["channel"],
                    delivered_at=datetime.fromisoformat(row["delivered_at"]),
                )
            if row["status"] == "SENDING" and row["attempted_at"] is not None:
                previous_attempt = datetime.fromisoformat(row["attempted_at"])
                lease_expires = previous_attempt + timedelta(seconds=lease_seconds)
                if attempted_at < lease_expires:
                    raise ValueError(
                        "incident notification dispatch is already in progress"
                    )
            connection.execute(
                "UPDATE notification_outbox SET status = 'SENDING', attempted_at = ?, "
                "attempt_count = attempt_count + 1 WHERE incident_id = ?",
                (attempted_at_text, incident_id),
            )
            notification = row["notification"]
        try:
            channel = sender(incident_id, notification)
            if channel not in {"audit-log", "webhook"}:
                raise ValueError("notification sender returned an unsupported channel")
        except Exception:
            with self._connection() as connection:
                connection.execute(
                    "UPDATE notification_outbox SET status = 'QUEUED' "
                    "WHERE incident_id = ? AND status = 'SENDING' AND attempted_at = ?",
                    (incident_id, attempted_at_text),
                )
            raise
        delivered_at = attempted_at
        with self._connection() as connection:
            updated = connection.execute(
                "UPDATE notification_outbox SET status = 'SENT', delivered_at = ?, "
                "channel = ? WHERE incident_id = ? AND status = 'SENDING' "
                "AND attempted_at = ?",
                (delivered_at.isoformat(), channel, incident_id, attempted_at_text),
            ).rowcount
            if updated != 1:
                raise RuntimeError("notification delivery state changed unexpectedly")
        return NotificationDispatchResponse(
            incident_id=incident_id,
            notification_status="SENT",
            channel=channel,
            delivered_at=delivered_at,
        )
