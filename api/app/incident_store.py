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
                CREATE TABLE IF NOT EXISTS notification_revisions (
                    incident_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    notification_key TEXT NOT NULL UNIQUE,
                    decision_fingerprint TEXT NOT NULL,
                    notification TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT,
                    channel TEXT,
                    attempted_at TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (incident_id, revision)
                );
                CREATE TABLE IF NOT EXISTS incident_decisions (
                    source_event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
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
            event_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(processed_events)")
            }
            for name in ("source_payload_sha256", "outcome_json"):
                if name not in event_columns:
                    connection.execute(f"ALTER TABLE processed_events ADD COLUMN {name} TEXT")
            for row in connection.execute("SELECT * FROM notification_outbox").fetchall():
                current = connection.execute(
                    "SELECT payload_json FROM incidents WHERE incident_id=?",
                    (row["incident_id"],),
                ).fetchone()
                fingerprint = hashlib.sha256(row["notification"].encode()).hexdigest()
                if current is not None:
                    try:
                        request = IncidentRecordRequest.model_validate_json(current[0])
                        if request.notification == row["notification"]:
                            fingerprint = self._notification_fingerprint(request)
                    except ValueError:
                        pass  # Preserve legacy delivery state even without a valid decision.
                connection.execute(
                    "INSERT OR IGNORE INTO notification_revisions VALUES "
                    "(?,1,?,?,?,?,?,?,?,?,?)",
                    (row["incident_id"], row["incident_id"], fingerprint,
                     row["notification"], row["status"], row["created_at"],
                     row["delivered_at"], row["channel"], row["attempted_at"],
                     row["attempt_count"]),
                )

    @staticmethod
    def _payload(request: IncidentRecordRequest) -> tuple[str, str]:
        payload = json.dumps(
            request.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        return payload, hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def _notification_fingerprint(request: IncidentRecordRequest) -> str:
        prediction = request.decision.get("prediction")
        prediction = prediction if isinstance(prediction, dict) else {}
        risk = request.decision.get("risk")
        risk = risk if isinstance(risk, dict) else {}
        state = {
            "route": request.route,
            "review_required": request.review_required,
            "notification": request.notification,
            "prediction": {name: prediction.get(name) for name in (
                "model_version", "predicted_class", "review_required", "ood_detected"
            )},
            "risk_display": risk.get("display"),
        }
        return hashlib.sha256(
            json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def get_event_outcome(
        self, source_event_id: str, *, payload_sha256: str
    ) -> IncidentRecordResponse | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT source_payload_sha256,outcome_json FROM processed_events "
                "WHERE source_event_id=?", (source_event_id,),
            ).fetchone()
        if row is None or row["source_payload_sha256"] is None:
            return None
        if row["source_payload_sha256"] != payload_sha256:
            raise ValueError("source_event_id was already processed with a different raw payload")
        if row["outcome_json"] is None:
            raise ValueError("processed event is missing its durable outcome")
        return IncidentRecordResponse.model_validate_json(row["outcome_json"]).model_copy(
            update={"disposition": "duplicate", "notification_status": "ALREADY_QUEUED"}
        )

    def record(self, request: IncidentRecordRequest) -> IncidentRecordResponse:
        payload, payload_hash = self._payload(request)
        now = datetime.now(UTC)
        now_text = now.isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            processed = connection.execute(
                "SELECT * FROM processed_events "
                "WHERE source_event_id = ?",
                (request.source_event_id,),
            ).fetchone()
            if processed is not None:
                raw_hash = request.source_payload_sha256
                if raw_hash is not None:
                    if processed["source_payload_sha256"] != raw_hash:
                        raise ValueError(
                            "source_event_id was already processed with a different raw payload"
                        )
                elif processed["payload_hash"] != payload_hash:
                    raise ValueError(
                        "source_event_id was already processed with a different decision"
                    )
                if processed["outcome_json"] is not None:
                    return IncidentRecordResponse.model_validate_json(
                        processed["outcome_json"]
                    ).model_copy(update={
                        "disposition": "duplicate", "notification_status": "ALREADY_QUEUED"
                    })
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
            latest = connection.execute(
                "SELECT revision,decision_fingerprint FROM notification_revisions "
                "WHERE incident_id=? ORDER BY revision DESC LIMIT 1",
                (request.incident_id,),
            ).fetchone()
            fingerprint = self._notification_fingerprint(request)
            queued = latest is None or latest["decision_fingerprint"] != fingerprint
            revision = int(latest["revision"]) if latest is not None else 0
            if queued:
                revision += 1
                connection.execute(
                    "UPDATE notification_revisions SET status='SUPERSEDED' "
                    "WHERE incident_id=? AND status='QUEUED'", (request.incident_id,),
                )
                connection.execute(
                    "INSERT INTO notification_revisions "
                    "(incident_id,revision,notification_key,decision_fingerprint,"
                    "notification,status,created_at) VALUES (?,?,?,?,?,'QUEUED',?)",
                    (request.incident_id, revision,
                     f"{request.incident_id}:notification:{revision}", fingerprint,
                     request.notification, now_text),
                )
            result = IncidentRecordResponse(
                incident_id=request.incident_id, source_event_id=request.source_event_id,
                disposition=disposition,
                notification_status="QUEUED" if queued else "ALREADY_QUEUED",
                notification_revision=revision, route=request.route,
                review_required=request.review_required, recorded_at=now,
            )
            connection.execute(
                "INSERT INTO processed_events "
                "(source_event_id,payload_hash,incident_id,processed_at,"
                "source_payload_sha256,outcome_json) VALUES (?,?,?,?,?,?)",
                (request.source_event_id, payload_hash, request.incident_id, now_text,
                 request.source_payload_sha256, result.model_dump_json()),
            )
            connection.execute(
                "INSERT INTO incident_decisions VALUES (?,?,?,?,?)",
                (request.source_event_id, request.incident_id, payload_hash, payload, now_text),
            )
        return result

    def dispatch_notification(
        self,
        incident_id: str,
        sender: Callable[[str, str, str], str],
        *,
        notification_revision: int | None = None,
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
            query = "SELECT * FROM notification_revisions WHERE incident_id=?"
            values: tuple = (incident_id,)
            if notification_revision is not None:
                query += " AND revision=?"
                values = (incident_id, notification_revision)
            row = connection.execute(query + " ORDER BY revision DESC LIMIT 1", values).fetchone()
            if row is None:
                raise ValueError("incident notification is not queued")
            revision = int(row["revision"])
            if row["status"] == "SUPERSEDED":
                latest_revision = connection.execute(
                    "SELECT MAX(revision) FROM notification_revisions WHERE incident_id=?",
                    (incident_id,),
                ).fetchone()[0]
                return NotificationDispatchResponse(
                    incident_id=incident_id, notification_revision=revision,
                    notification_status="SUPERSEDED",
                    superseded_by_revision=int(latest_revision),
                )
            if row["status"] == "SENT":
                return NotificationDispatchResponse(
                    incident_id=incident_id,
                    notification_revision=revision,
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
                "UPDATE notification_revisions SET status = 'SENDING', attempted_at = ?, "
                "attempt_count = attempt_count + 1 WHERE incident_id = ? AND revision=?",
                (attempted_at_text, incident_id, revision),
            )
            notification = row["notification"]
        try:
            channel = sender(incident_id, notification, row["notification_key"])
            if channel not in {"audit-log", "webhook"}:
                raise ValueError("notification sender returned an unsupported channel")
        except Exception:
            with self._connection() as connection:
                connection.execute(
                    "UPDATE notification_revisions SET status = CASE WHEN EXISTS ("
                    "SELECT 1 FROM notification_revisions newer WHERE "
                    "newer.incident_id=notification_revisions.incident_id "
                    "AND newer.revision>notification_revisions.revision) "
                    "THEN 'SUPERSEDED' ELSE 'QUEUED' END "
                    "WHERE incident_id = ? AND revision=? AND status = 'SENDING' "
                    "AND attempted_at = ?", (incident_id, revision, attempted_at_text),
                )
            raise
        delivered_at = attempted_at
        with self._connection() as connection:
            updated = connection.execute(
                "UPDATE notification_revisions SET status = 'SENT', delivered_at = ?, "
                "channel = ? WHERE incident_id = ? AND revision=? AND status = 'SENDING' "
                "AND attempted_at = ?",
                (delivered_at.isoformat(), channel, incident_id, revision, attempted_at_text),
            ).rowcount
            if updated != 1:
                raise RuntimeError("notification delivery state changed unexpectedly")
        return NotificationDispatchResponse(
            incident_id=incident_id,
            notification_revision=revision,
            notification_status="SENT",
            channel=channel,
            delivered_at=delivered_at,
        )
