from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from api.app.contracts import FeatureStateResponse, WazuhAlert
from ml.behavior_features import FEATURE_SCHEMA_VERSION
from ml.feature_pipeline import aggregate_wazuh_alerts, alert_event_time, window_start
from ml.intake_window import receipt_timely


class FeatureStateConflictError(ValueError):
    """An alert ID was replayed with a different payload."""


class FeatureStateStore:
    """Durable, bounded alert window used by the online feature pipeline."""

    def __init__(
        self, path: Path, *, retention_seconds: int = 86_400,
        late_arrival_grace_seconds: int = 60,
    ) -> None:
        if retention_seconds < 300:
            raise ValueError("retention_seconds must be at least 300")
        self.path = path
        self.retention_seconds = retention_seconds
        if not 0 <= late_arrival_grace_seconds <= 600:
            raise ValueError("late_arrival_grace_seconds must be in [0,600]")
        self.late_arrival_grace_seconds = late_arrival_grace_seconds
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
                    received_at REAL NOT NULL,
                    feature_schema_version TEXT NOT NULL DEFAULT 'features-v3'
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ix_wazuh_event_timestamp "
                "ON wazuh_alerts(event_timestamp)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS closed_feature_windows ("
                "incident_id TEXT PRIMARY KEY, input_hash TEXT NOT NULL, "
                "response_json TEXT NOT NULL, closed_at REAL NOT NULL)"
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(wazuh_alerts)")}
            # Keep legacy rows for audit/TTL; only the current feature schema
            # participates in new fixed windows.
            if "feature_response_json" not in columns:
                connection.execute("ALTER TABLE wazuh_alerts ADD COLUMN feature_response_json TEXT")
            if "window_minutes" not in columns:
                connection.execute("ALTER TABLE wazuh_alerts ADD COLUMN window_minutes INTEGER")
            if "feature_schema_version" not in columns:
                connection.execute(
                    "ALTER TABLE wazuh_alerts ADD COLUMN feature_schema_version "
                    "TEXT NOT NULL DEFAULT 'features-v2'"
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
            connection.execute(
                "DELETE FROM closed_feature_windows WHERE closed_at < ?",
                (now - self.retention_seconds,),
            )
            existing = connection.execute(
                "SELECT payload_hash, feature_response_json, window_minutes, "
                "feature_schema_version "
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
                    or existing["feature_schema_version"] != FEATURE_SCHEMA_VERSION
                ):
                    raise FeatureStateConflictError(
                        "original fixed-window response is unavailable for this legacy event "
                        "or the requested window has changed; use the persisted event outcome"
                    )
                try:
                    original = FeatureStateResponse.model_validate_json(
                        existing["feature_response_json"]
                    )
                except ValueError as exc:
                    raise FeatureStateConflictError(
                        "cached legacy/schema response is unavailable; use persisted event outcome"
                    ) from exc
                return original.model_copy(update={"ingest_status": "duplicate"})
            connection.execute(
                "INSERT INTO wazuh_alerts "
                "(alert_id, payload_hash, payload_json, event_timestamp, "
                "received_at, window_minutes, feature_schema_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (alert.id, payload_hash, payload, event_time, now, window_minutes,
                 FEATURE_SCHEMA_VERSION),
            )
            rows = connection.execute(
                """
                SELECT payload_json FROM wazuh_alerts
                WHERE event_timestamp >= ? AND event_timestamp < ?
                  AND window_minutes = ?
                  AND feature_schema_version = ?
                ORDER BY event_timestamp, alert_id
                """,
                (bucket_start, bucket_start + horizon, window_minutes, FEATURE_SCHEMA_VERSION),
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
            close_at = bucket_start + horizon + self.late_arrival_grace_seconds
            reason = "window:open" if receipt_timely(
                datetime.fromtimestamp(now, UTC), datetime.fromtimestamp(close_at, UTC),
            ) else "window:late_arrival"
            # Ingest responses are provisional, not a window-close watermark.
            # A later explicit close/reconciliation must approve a final decision.
            feature = feature.model_copy(update={
                "quality_status": "PARTIAL",
                "incident": feature.incident.model_copy(update={
                    "observation_quality": "PARTIAL",
                    "review_reasons": sorted(set([*feature.incident.review_reasons, reason])),
                }),
            })
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

    def finalize_window(self, alert_id: str, *, window_minutes: int = 5) -> FeatureStateResponse:
        """Close a complete raw window after its watermark, preserving immutable outcomes.

        New raw input after the grace deadline invalidates reconciliation. It can
        still be inspected through ingest, but must not silently rewrite an
        already approved close result.
        """
        now = time.time()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            anchor = connection.execute(
                "SELECT * FROM wazuh_alerts WHERE alert_id=?", (alert_id,),
            ).fetchone()
            if anchor is None or (
                anchor['feature_schema_version'] != FEATURE_SCHEMA_VERSION
                or anchor['window_minutes'] != window_minutes
            ):
                raise FeatureStateConflictError("window anchor is missing or uses a legacy schema")
            alert = WazuhAlert.model_validate_json(anchor['payload_json'])
            start = window_start(alert, window_minutes=window_minutes).timestamp()
            end = start + window_minutes * 60
            close_at = end + self.late_arrival_grace_seconds
            if now < close_at:
                raise FeatureStateConflictError("window close watermark has not been reached")
            rows = connection.execute(
                "SELECT * FROM wazuh_alerts WHERE event_timestamp>=? AND event_timestamp<? "
                "AND window_minutes=? AND feature_schema_version=? ORDER BY alert_id",
                (start, end, window_minutes, FEATURE_SCHEMA_VERSION),
            ).fetchall()
            batch = aggregate_wazuh_alerts(
                [WazuhAlert.model_validate_json(row['payload_json']) for row in rows],
                window_minutes=window_minutes,
            )
            feature = next(
                item for item in batch.incidents
                if f'wazuh-alert:{alert_id}' in item.incident.raw_refs
            )
            references = set(feature.incident.raw_refs)
            members = [row for row in rows if f"wazuh-alert:{row['alert_id']}" in references]
            if any(not receipt_timely(
                datetime.fromtimestamp(row['received_at'], UTC),
                datetime.fromtimestamp(close_at, UTC),
            ) for row in members):
                raise FeatureStateConflictError("late input changed the window after its watermark")
            if any(row['received_at'] < now - self.retention_seconds for row in members):
                raise FeatureStateConflictError("window close exceeds raw retention; recollect")
            digest = hashlib.sha256(json.dumps([
                (row['alert_id'], row['payload_hash']) for row in members
            ], separators=(',', ':')).encode()).hexdigest()
            previous = connection.execute(
                "SELECT * FROM closed_feature_windows WHERE incident_id=?",
                (feature.incident.incident_id,),
            ).fetchone()
            if previous is not None:
                if previous['input_hash'] != digest:
                    raise FeatureStateConflictError("raw input changed after window closure")
                return FeatureStateResponse.model_validate_json(
                    previous['response_json'],
                ).model_copy(update={'ingest_status': 'duplicate'})
            result = FeatureStateResponse(
                ingest_status='new', stored_event_count=len(members),
                window_minutes=window_minutes, feature=feature,
            )
            connection.execute(
                "INSERT INTO closed_feature_windows VALUES (?,?,?,?)",
                (feature.incident.incident_id, digest, result.model_dump_json(), now),
            )
            return result
