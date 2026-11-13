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
from ml.telemetry import EVENT_TIME_POLICY_VERSION, process_guid, windows_fields


class FeatureStateConflictError(ValueError):
    """Stored evidence or derived state cannot safely satisfy this request."""


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
        # Inspect before enabling WAL or running any schema upgrade. Old caches
        # contain derived timestamps and responses that cannot be reinterpreted
        # just because their raw payload hashes still match.
        if self.path.exists():
            connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                self._check_time_policy(connection)
            finally:
                connection.close()
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
            connection.execute(
                "CREATE TABLE IF NOT EXISTS feature_snapshot_sequence ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL)"
            )
            connection.execute("INSERT OR IGNORE INTO feature_snapshot_sequence VALUES (1,0)")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS evicted_feature_windows ("
                "bucket_start REAL NOT NULL, window_minutes INTEGER NOT NULL, "
                "feature_schema_version TEXT NOT NULL, "
                "PRIMARY KEY(bucket_start,window_minutes,feature_schema_version))"
            )
            closed_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(closed_feature_windows)")
            }
            if "legacy_response_json" not in closed_columns:
                connection.execute(
                    "ALTER TABLE closed_feature_windows ADD COLUMN legacy_response_json TEXT"
                )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(wazuh_alerts)")}
            # Keep legacy rows for audit/TTL; only the current feature schema
            # participates in new fixed windows.
            if "feature_response_json" not in columns:
                connection.execute("ALTER TABLE wazuh_alerts ADD COLUMN feature_response_json TEXT")
            if "legacy_feature_response_json" not in columns:
                connection.execute(
                    "ALTER TABLE wazuh_alerts ADD COLUMN legacy_feature_response_json TEXT"
                )
            if "window_minutes" not in columns:
                connection.execute("ALTER TABLE wazuh_alerts ADD COLUMN window_minutes INTEGER")
            if "feature_schema_version" not in columns:
                connection.execute(
                    "ALTER TABLE wazuh_alerts ADD COLUMN feature_schema_version "
                    "TEXT NOT NULL DEFAULT 'features-v2'"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS process_identity_events ("
                "alert_id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL, "
                "payload_json TEXT NOT NULL, "
                "event_timestamp REAL NOT NULL, received_at REAL NOT NULL, "
                "agent_name TEXT NOT NULL, process_guid TEXT NOT NULL, event_kind TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ix_process_identity_scope "
                "ON process_identity_events(agent_name,process_guid,event_timestamp)"
            )
            # Upgrade from retained raw evidence only, never reconstructed features.
            for row in connection.execute(
                "SELECT * FROM wazuh_alerts WHERE feature_schema_version=?",
                (FEATURE_SCHEMA_VERSION,),
            ).fetchall():
                self._retain_process_identity(
                    connection, WazuhAlert.model_validate_json(row["payload_json"]),
                    row["payload_json"], row["payload_hash"],
                    row["event_timestamp"], row["received_at"],
                    migration=True,
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS feature_time_policy ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), version TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO feature_time_policy VALUES (1,?)",
                (EVENT_TIME_POLICY_VERSION,),
            )

    @staticmethod
    def _check_time_policy(connection: sqlite3.Connection) -> None:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'",
        )}
        error = (
            "feature-state chronology policy is missing or incompatible; preserve this "
            "database and select a fresh database path for new collection or explicit raw replay"
        )
        if "feature_time_policy" in tables:
            versions = connection.execute("SELECT version FROM feature_time_policy").fetchall()
            if versions != [(EVENT_TIME_POLICY_VERSION,)]:
                raise FeatureStateConflictError(error)
            return
        # Prior schema generations never participate in current windows. Keep
        # their existing audit-only migration, provided no current derived state
        # or retained process identity accompanies them.
        if "wazuh_alerts" in tables:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(wazuh_alerts)")}
            legacy_columns = {"alert_id", "payload_hash", "payload_json",
                              "event_timestamp", "received_at"}
            if "feature_schema_version" in columns:
                current = connection.execute(
                    "SELECT 1 FROM wazuh_alerts WHERE feature_schema_version IS NULL "
                    "OR feature_schema_version NOT IN ('features-v1','features-v2') LIMIT 1",
                ).fetchone()
            elif legacy_columns <= columns:
                current = None
            else:
                current = connection.execute("SELECT 1 FROM wazuh_alerts LIMIT 1").fetchone()
            if current:
                raise FeatureStateConflictError(error)
        for table in (
            "process_identity_events", "closed_feature_windows", "evicted_feature_windows",
        ):
            if table in tables and connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                raise FeatureStateConflictError(error)

    def _retain_process_identity(
        self, connection: sqlite3.Connection, alert: WazuhAlert, payload: str,
        payload_hash: str, event_time: float, received_at: float, *, migration: bool = False,
    ) -> None:
        previous = connection.execute(
            "SELECT payload_hash FROM process_identity_events WHERE alert_id=?", (alert.id,),
        ).fetchone()
        if previous is not None and previous[0] != payload_hash:
            raise FeatureStateConflictError(
                f"alert id {alert.id!r} was replayed with a conflicting payload"
            )
        event_id, _, fields = windows_fields(alert.model_dump(mode="json"))
        guid = process_guid(fields)
        if event_id not in {"1", "5"} or not guid:
            return
        if previous is None and event_id == "1" and event_time < (
            received_at - self.retention_seconds
        ):
            # An active proof already retained above remains usable. An absent
            # expired start cannot recreate a lifetime whose exit was evicted.
            if migration:
                return
            raise FeatureStateConflictError("stale process creation exceeds identity retention")
        connection.execute(
            "INSERT OR IGNORE INTO process_identity_events VALUES (?,?,?,?,?,?,?,?)",
            (alert.id, payload_hash, payload, event_time, received_at,
             alert.agent.name, guid, event_id),
        )

    @staticmethod
    def _process_context(
        connection: sqlite3.Connection, alerts: list[WazuhAlert],
    ) -> list[sqlite3.Row]:
        """Return only same-agent/GUID lifecycle proof as of an observed network event."""
        identities = {}
        for alert in alerts:
            event_id, _, fields = windows_fields(alert.model_dump(mode="json"))
            guid = process_guid(fields)
            if event_id not in {"3", "22"} or not guid:
                continue
            for row in connection.execute(
                "SELECT * FROM process_identity_events WHERE agent_name=? AND process_guid=? "
                "AND event_timestamp<=? ORDER BY event_timestamp,alert_id",
                (alert.agent.name, guid, alert_event_time(alert).timestamp()),
            ).fetchall():
                identities[row["alert_id"]] = row
        return sorted(identities.values(), key=lambda row: row["alert_id"])

    @staticmethod
    def _next_revision(connection: sqlite3.Connection) -> int:
        connection.execute(
            "UPDATE feature_snapshot_sequence SET revision=revision+1 WHERE singleton=1"
        )
        return int(connection.execute(
            "SELECT revision FROM feature_snapshot_sequence WHERE singleton=1"
        ).fetchone()[0])

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
            self._retain_process_identity(connection, alert, payload, payload_hash, event_time, now)
            # Open processes retain their original proof for their lifetime.
            # Closed lifetimes can expire once no retained window may need them.
            connection.execute(
                "DELETE FROM process_identity_events AS identity WHERE EXISTS ("
                "SELECT 1 FROM process_identity_events exited "
                "WHERE exited.agent_name=identity.agent_name "
                "AND exited.process_guid=identity.process_guid AND exited.event_kind='5' "
                "AND exited.event_timestamp>=identity.event_timestamp "
                "AND exited.event_timestamp<? AND exited.received_at<?)",
                (now - self.retention_seconds, now - self.retention_seconds),
            )
            # Persist loss evidence before deleting raw rows. A surviving anchor
            # alone cannot prove the window still contains every original member.
            connection.execute(
                "INSERT OR IGNORE INTO evicted_feature_windows "
                "SELECT CAST(event_timestamp/(window_minutes*60) AS INTEGER)*(window_minutes*60), "
                "window_minutes, feature_schema_version FROM wazuh_alerts "
                "WHERE received_at < ? AND window_minutes IS NOT NULL",
                (now - self.retention_seconds,),
            )
            connection.execute(
                "DELETE FROM evicted_feature_windows WHERE bucket_start + window_minutes*60 < ?",
                (now - self.retention_seconds,),
            )
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
                if original.snapshot_revision is not None:
                    return original.model_copy(update={"ingest_status": "duplicate"})
                # Never label a historical cached observation as a newer snapshot.
                # Retain its bytes for audit, then rebuild current provisional facts
                # below from all surviving raw input under this same transaction.
                connection.execute(
                    "UPDATE wazuh_alerts SET legacy_feature_response_json="
                    "COALESCE(legacy_feature_response_json,feature_response_json) WHERE alert_id=?",
                    (alert.id,),
                )
            if existing is None:
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
            identities = self._process_context(connection, alerts)
            batch = aggregate_wazuh_alerts(
                alerts, window_minutes=window_minutes,
                process_context=[
                    WazuhAlert.model_validate_json(row["payload_json"]) for row in identities
                ],
            )
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
            legacy_reasons = ["window:legacy_rebuilt"] if existing is not None else []
            # Ingest responses are provisional, not a window-close watermark.
            # A later explicit close/reconciliation must approve a final decision.
            feature = feature.model_copy(update={
                "quality_status": "PARTIAL",
                "incident": feature.incident.model_copy(update={
                    "observation_quality": "PARTIAL",
                    "review_reasons": sorted(set([
                        *feature.incident.review_reasons, reason, *legacy_reasons,
                    ])),
                }),
            })
            result = FeatureStateResponse(
                snapshot_revision=self._next_revision(connection),
                ingest_status="duplicate" if existing is not None else "new",
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
            if start < now - self.retention_seconds or connection.execute(
                "SELECT 1 FROM evicted_feature_windows WHERE bucket_start=? "
                "AND window_minutes=? AND feature_schema_version=?",
                (start, window_minutes, FEATURE_SCHEMA_VERSION),
            ).fetchone() is not None:
                raise FeatureStateConflictError(
                    "window exceeds raw retention or contains evicted input; recollect"
                )
            if now < close_at:
                raise FeatureStateConflictError("window close watermark has not been reached")
            rows = connection.execute(
                "SELECT * FROM wazuh_alerts WHERE event_timestamp>=? AND event_timestamp<? "
                "AND window_minutes=? AND feature_schema_version=? ORDER BY alert_id",
                (start, end, window_minutes, FEATURE_SCHEMA_VERSION),
            ).fetchall()
            alerts = [WazuhAlert.model_validate_json(row['payload_json']) for row in rows]
            identities = self._process_context(connection, alerts)
            batch = aggregate_wazuh_alerts(
                alerts,
                window_minutes=window_minutes,
                process_context=[
                    WazuhAlert.model_validate_json(row["payload_json"]) for row in identities
                ],
            )
            feature = next(
                item for item in batch.incidents
                if f'wazuh-alert:{alert_id}' in item.incident.raw_refs
            )
            references = set(feature.incident.raw_refs)
            members = [row for row in rows if f"wazuh-alert:{row['alert_id']}" in references]
            member_alerts = [WazuhAlert.model_validate_json(row["payload_json"]) for row in members]
            identities = self._process_context(connection, member_alerts)
            if any(not receipt_timely(
                datetime.fromtimestamp(row['received_at'], UTC),
                datetime.fromtimestamp(close_at, UTC),
            ) for row in [*members, *identities]):
                raise FeatureStateConflictError("late input changed the window after its watermark")
            if any(row['received_at'] < now - self.retention_seconds for row in members):
                raise FeatureStateConflictError("window close exceeds raw retention; recollect")
            evidence = {row['alert_id']: row['payload_hash'] for row in [*members, *identities]}
            digest = hashlib.sha256(json.dumps(
                sorted(evidence.items()), separators=(',', ':'),
            ).encode()).hexdigest()
            previous = connection.execute(
                "SELECT * FROM closed_feature_windows WHERE incident_id=?",
                (feature.incident.incident_id,),
            ).fetchone()
            if previous is not None:
                if previous['input_hash'] != digest:
                    raise FeatureStateConflictError("raw input changed after window closure")
                original = FeatureStateResponse.model_validate_json(previous['response_json'])
                if original.snapshot_revision is not None:
                    return original.model_copy(update={'ingest_status': 'duplicate'})
                # A legacy close may be migrated only after the same full raw
                # digest and watermark checks above succeed. Rebuild its current
                # facts rather than assigning a new revision to historical JSON.
            result = FeatureStateResponse(
                snapshot_revision=self._next_revision(connection),
                ingest_status='duplicate' if previous is not None else 'new',
                stored_event_count=len(members),
                window_minutes=window_minutes, feature=feature,
            )
            if previous is None:
                connection.execute(
                    "INSERT INTO closed_feature_windows "
                    "(incident_id,input_hash,response_json,closed_at) VALUES (?,?,?,?)",
                    (feature.incident.incident_id, digest, result.model_dump_json(), now),
                )
            else:
                connection.execute(
                    "UPDATE closed_feature_windows SET legacy_response_json="
                    "COALESCE(legacy_response_json,response_json),response_json=? "
                    "WHERE incident_id=?",
                    (result.model_dump_json(), feature.incident.incident_id),
                )
            return result
