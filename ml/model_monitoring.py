from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path


class ModelMonitoringStore:
    """Aggregate prediction telemetry without retaining incident feature values."""

    def __init__(self, path: Path | None) -> None:
        self.persistent = path is not None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
        target = str(path) if path is not None else ":memory:"
        self._connection = sqlite3.connect(target, timeout=10, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA busy_timeout=10000")
        if self.persistent:
            self._connection.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS model_prediction_metrics (
                    model_version TEXT NOT NULL,
                    family TEXT NOT NULL,
                    predictions_total INTEGER NOT NULL,
                    review_required_total INTEGER NOT NULL,
                    ood_total INTEGER NOT NULL,
                    ood_by_feature_json TEXT NOT NULL,
                    first_prediction_at TEXT NOT NULL,
                    last_prediction_at TEXT NOT NULL,
                    PRIMARY KEY (model_version, family)
                )
                """
            )

    def record_prediction(
        self,
        *,
        model_version: str,
        family: str,
        review_required: bool,
        ood_features: list[str],
        recorded_at: datetime | None = None,
    ) -> None:
        timestamp = recorded_at or datetime.now(UTC)
        timestamp_text = timestamp.astimezone(UTC).isoformat()
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT ood_by_feature_json FROM model_prediction_metrics "
                "WHERE model_version = ? AND family = ?",
                (model_version, family),
            ).fetchone()
            feature_counts = json.loads(row["ood_by_feature_json"]) if row else {}
            for name in set(ood_features):
                feature_counts[name] = int(feature_counts.get(name, 0)) + 1
            self._connection.execute(
                """
                INSERT INTO model_prediction_metrics (
                    model_version, family, predictions_total,
                    review_required_total, ood_total, ood_by_feature_json,
                    first_prediction_at, last_prediction_at
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?)
                ON CONFLICT(model_version, family) DO UPDATE SET
                    predictions_total = predictions_total + 1,
                    review_required_total = review_required_total + excluded.review_required_total,
                    ood_total = ood_total + excluded.ood_total,
                    ood_by_feature_json = excluded.ood_by_feature_json,
                    last_prediction_at = excluded.last_prediction_at
                """,
                (
                    model_version,
                    family,
                    int(review_required),
                    int(bool(ood_features)),
                    json.dumps(feature_counts, sort_keys=True, separators=(",", ":")),
                    timestamp_text,
                    timestamp_text,
                ),
            )

    def snapshot(self, model_version: str, families: list[str]) -> dict[str, object]:
        predictions_by_family = {family: 0 for family in families}
        ood_by_family = {family: 0 for family in families}
        ood_by_feature: dict[str, int] = {}
        review_required_total = 0
        last_prediction_at: datetime | None = None
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM model_prediction_metrics WHERE model_version = ?",
                (model_version,),
            ).fetchall()
        for row in rows:
            family = str(row["family"])
            predictions_by_family[family] = int(row["predictions_total"])
            ood_by_family[family] = int(row["ood_total"])
            review_required_total += int(row["review_required_total"])
            for name, count in json.loads(row["ood_by_feature_json"]).items():
                ood_by_feature[name] = ood_by_feature.get(name, 0) + int(count)
            candidate = datetime.fromisoformat(row["last_prediction_at"])
            if last_prediction_at is None or candidate > last_prediction_at:
                last_prediction_at = candidate
        return {
            "monitoring_storage": "sqlite" if self.persistent else "memory",
            "predictions_total": sum(predictions_by_family.values()),
            "predictions_by_family": predictions_by_family,
            "review_required_total": review_required_total,
            "ood_total": sum(ood_by_family.values()),
            "ood_by_family": ood_by_family,
            "ood_by_feature": dict(sorted(ood_by_feature.items())),
            "last_prediction_at": last_prediction_at,
        }
