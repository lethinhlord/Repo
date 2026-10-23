from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

from api.app.contracts import FeatureStateResponse, WazuhAlert
from ml.feature_pipeline import aggregate_wazuh_alerts


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

    def _initialize(self) -> None:
        with self._connect() as connection:
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
        event_time = alert.timestamp.timestamp()
        now = time.time()
        horizon = window_minutes * 60
        duplicate = False

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM wazuh_alerts WHERE received_at < ?",
                (now - self.retention_seconds,),
            )
            existing = connection.execute(
                "SELECT payload_hash FROM wazuh_alerts WHERE alert_id = ?",
                (alert.id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    raise FeatureStateConflictError(
                        f"alert id {alert.id!r} was replayed with a conflicting payload"
                    )
                duplicate = True
            else:
                connection.execute(
                    "INSERT INTO wazuh_alerts VALUES (?, ?, ?, ?, ?)",
                    (alert.id, payload_hash, payload, event_time, now),
                )
            rows = connection.execute(
                """
                SELECT payload_json FROM wazuh_alerts
                WHERE event_timestamp >= ? AND event_timestamp < ?
                ORDER BY event_timestamp, alert_id
                """,
                (event_time - horizon, event_time + horizon),
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
        return FeatureStateResponse(
            ingest_status="duplicate" if duplicate else "new",
            stored_event_count=len(alerts),
            window_minutes=window_minutes,
            feature=feature,
        )
