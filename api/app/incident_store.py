from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from api.app.contracts import IncidentRecordRequest, IncidentRecordResponse


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

    def _initialize(self) -> None:
        with self._connect() as connection:
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
                    created_at TEXT NOT NULL
                );
                """
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
        with self._connect() as connection:
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
                "INSERT OR IGNORE INTO notification_outbox VALUES (?, ?, 'QUEUED', ?)",
                (request.incident_id, request.notification, now_text),
            ).rowcount

        return IncidentRecordResponse(
            incident_id=request.incident_id,
            source_event_id=request.source_event_id,
            disposition=disposition,
            notification_status="QUEUED" if queued else "ALREADY_QUEUED",
            recorded_at=now,
        )
