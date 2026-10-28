from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from api.app.contracts import FeatureStateResponse, WazuhAlert
from ml.feature_pipeline import aggregate_wazuh_alerts, alert_event_time, window_start


class FeatureStateConflictError(ValueError):
    """An alert ID was replayed with a different payload."""


class FeatureStateStore:
    """Durable, bounded alert window used by the online feature pipeline."""

    def __init__(self, path: Path, *, retention_seconds: int = 86_400) -> None:
        if retention_seconds < 300:
            raise ValueError("retention_seconds must be at least 300")
        self.path = path
        self.retention_seconds = retention_seconds
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS wazuh_alerts (
                    alert_id TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    event_timestamp REAL NOT NULL,
                    received_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ix_wazuh_event_timestamp "
                "ON wazuh_alerts(event_timestamp)"
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(wazuh_alerts)")}
            # Keep v1 rows for audit/TTL. Their original feature cannot be recreated
            # after the fact, so only new v2 rows participate in fixed windows.
            if "feature_response_json" not in columns:
                connection.execute("ALTER TABLE wazuh_alerts ADD COLUMN feature_response_json TEXT")
            if "window_minutes" not in columns:
                connection.execute("ALTER TABLE wazuh_alerts ADD COLUMN window_minutes INTEGER")

    @staticmethod
    def _serialize(alert: WazuhAlert) -> tuple[str, str]:
        payload = json.dumps(
            alert.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        return payload, hashlib.sha256(payload.encode()).hexdigest()

    def ingest(self, alert: WazuhAlert, *, window_minutes: int = 5) -> FeatureStateResponse:
        if not 1 <= window_minutes <= 5:
            raise ValueError("window_minutes must be between 1 and 5")
        payload, payload_hash = self._serialize(alert)
        event_time = alert_event_time(alert).timestamp()
        now = time.time()
        horizon = window_minutes * 60
        bucket_start = window_start(alert, window_minutes=window_minutes).timestamp()

        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM wazuh_alerts WHERE received_at < ?",
                (now - self.retention_seconds,),
            )
            existing = connection.execute(
                "SELECT payload_hash, feature_response_json, window_minutes "
                "FROM wazuh_alerts WHERE alert_id = ?",
                (alert.id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    raise FeatureStateConflictError(
                        f"alert id {alert.id!r} was replayed with a conflicting payload"
                    )
                if (
                    existing["feature_response_json"] is None
                    or existing["window_minutes"] != window_minutes
                ):
                    raise FeatureStateConflictError(
                        "original fixed-window response is unavailable for this legacy event "
                        "or the requested window has changed; use the persisted event outcome"
                    )
                original = FeatureStateResponse.model_validate_json(
                    existing["feature_response_json"]
                )
                return original.model_copy(update={"ingest_status": "duplicate"})
            connection.execute(
                "INSERT INTO wazuh_alerts "
                "(alert_id, payload_hash, payload_json, event_timestamp, "
                "received_at, window_minutes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (alert.id, payload_hash, payload, event_time, now, window_minutes),
            )
            rows = connection.execute(
                """
                SELECT payload_json FROM wazuh_alerts
                WHERE event_timestamp >= ? AND event_timestamp < ?
                  AND window_minutes = ?
                ORDER BY event_timestamp, alert_id
                """,
                (bucket_start, bucket_start + horizon, window_minutes),
            ).fetchall()
            alerts = [WazuhAlert.model_validate_json(row["payload_json"]) for row in rows]
            batch = aggregate_wazuh_alerts(alerts, window_minutes=window_minutes)
            reference = f"wazuh-alert:{alert.id}"
            feature = next(
                (item for item in batch.incidents if reference in item.incident.raw_refs),
                None,
            )
            if feature is None:  # pragma: no cover - invariant guard
                raise RuntimeError("stored alert was not present in its aggregation result")
            result = FeatureStateResponse(
                ingest_status="new",
                stored_event_count=sum(
                    value.startswith("wazuh-alert:") for value in feature.incident.raw_refs
                ),
                window_minutes=window_minutes,
                feature=feature,
            )
            connection.execute(
                "UPDATE wazuh_alerts SET feature_response_json = ? WHERE alert_id = ?",
                (result.model_dump_json(), alert.id),
            )
            return result
