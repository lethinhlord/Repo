from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from api.app.contracts import AnalystFeedbackRequest, AnalystFeedbackResponse


class AnalystFeedbackStore:
    """Append-only analyst feedback ledger for model monitoring and retraining."""

    def __init__(self, path: Path, incident_path: Path) -> None:
        self.path = path
        self.incident_path = incident_path
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
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    analyst_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    UNIQUE (incident_id, model_version, analyst_id)
                )
                ;
                CREATE TABLE IF NOT EXISTS analyst_feedback_reviews (
                    feedback_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    decision_sha256 TEXT NOT NULL,
                    prediction_json TEXT,
                    analyst_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    decision_recorded_at TEXT NOT NULL,
                    UNIQUE (incident_id, model_version, decision_sha256, analyst_id)
                );
                INSERT OR IGNORE INTO analyst_feedback_reviews
                SELECT feedback_id,incident_id,model_version,'legacy-unverified',NULL,
                    analyst_id,payload_hash,payload_json,recorded_at,recorded_at
                    FROM analyst_feedback;
                """
            )

    def _validate_incident_reference(
        self, request: AnalystFeedbackRequest
    ) -> tuple[str, dict[str, object], str]:
        if not self.incident_path.is_file():
            raise ValueError("incident ledger is unavailable; feedback cannot be orphaned")
        connection = sqlite3.connect(self.incident_path, timeout=10)
        try:
            row = connection.execute(
                "SELECT payload_json,updated_at FROM incidents WHERE incident_id = ?",
                (request.incident_id,),
            ).fetchone()
            history_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='incident_decisions'"
            ).fetchone()
            if request.source_event_id is not None:
                history = connection.execute(
                    "SELECT payload_json,recorded_at FROM incident_decisions "
                    "WHERE incident_id=? AND source_event_id=?",
                    (request.incident_id, request.source_event_id),
                ).fetchall() if history_exists else []
                if not history:
                    raise ValueError("feedback source_event_id does not match incident history")
                candidates = history
            else:
                history = connection.execute(
                    "SELECT payload_json,recorded_at FROM incident_decisions WHERE incident_id=? "
                    "ORDER BY recorded_at DESC,rowid DESC", (request.incident_id,),
                ).fetchall() if history_exists else []
                candidates = (row, *history)
        finally:
            connection.close()
        if row is None:
            raise ValueError("feedback references an unknown incident")
        prediction = None
        for candidate in candidates:
            try:
                observed = json.loads(candidate[0])["decision"]["prediction"]
                if (
                    isinstance(observed, dict)
                    and observed.get("model_version") == request.model_version
                ):
                    prediction = observed
                    decision_recorded_at = str(candidate[1])
                    break
            except (KeyError, TypeError, json.JSONDecodeError):
                continue
        if prediction is None:
            raise ValueError("feedback model_version does not match the incident decision")
        predicted_class = prediction.get("predicted_class")
        if predicted_class not in {"benign", "malicious"}:
            raise ValueError("incident prediction lacks a valid predicted_class")
        required_prediction = {
            "true_positive": "malicious", "false_positive": "malicious",
            "true_negative": "benign", "false_negative": "benign",
        }.get(request.disposition)
        if required_prediction is not None and required_prediction != predicted_class:
            raise ValueError("feedback disposition contradicts stored predicted_class")
        canonical = json.dumps(prediction, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest(), prediction, decision_recorded_at

    @staticmethod
    def _identity(request: AnalystFeedbackRequest, decision_sha256: str) -> str:
        identity = "\x1f".join(
            (request.incident_id, request.model_version, decision_sha256, request.analyst_id)
        )
        return hashlib.sha256(identity.encode()).hexdigest()

    @staticmethod
    def _payload(request: AnalystFeedbackRequest) -> tuple[str, str]:
        payload = json.dumps(
            request.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        return payload, hashlib.sha256(payload.encode()).hexdigest()

    def record(self, request: AnalystFeedbackRequest) -> AnalystFeedbackResponse:
        decision_sha256, prediction, decision_recorded_at = (
            self._validate_incident_reference(request)
        )
        feedback_id = self._identity(request, decision_sha256)
        payload, payload_hash = self._payload(request)
        now = datetime.now(UTC)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload_hash, recorded_at FROM analyst_feedback_reviews "
                "WHERE feedback_id = ?",
                (feedback_id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    raise ValueError(
                        "feedback identity already exists with different content; "
                        "submit a new analyst identity for an independent review"
                    )
                return AnalystFeedbackResponse(
                    feedback_id=feedback_id,
                    incident_id=request.incident_id,
                    model_version=request.model_version,
                    disposition="duplicate",
                    recorded_at=datetime.fromisoformat(existing["recorded_at"]),
                )
            connection.execute(
                "INSERT INTO analyst_feedback_reviews VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    feedback_id,
                    request.incident_id,
                    request.model_version,
                    decision_sha256,
                    json.dumps(prediction, sort_keys=True, separators=(",", ":")),
                    request.analyst_id,
                    payload_hash,
                    payload,
                    now.isoformat(),
                    decision_recorded_at,
                ),
            )
        return AnalystFeedbackResponse(
            feedback_id=feedback_id,
            incident_id=request.incident_id,
            model_version=request.model_version,
            disposition="created",
            recorded_at=now,
        )

    def summary(self, model_version: str) -> dict[str, object]:
        dispositions = {
            "true_positive": 0,
            "false_positive": 0,
            "true_negative": 0,
            "false_negative": 0,
            "needs_investigation": 0,
        }
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT incident_id,decision_sha256,payload_json,recorded_at,"
                "decision_recorded_at,rowid "
                "FROM analyst_feedback_reviews WHERE model_version = ? "
                "ORDER BY recorded_at,rowid",
                (model_version,),
            ).fetchall()
        cases: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for row in rows:
            cases[row["incident_id"]].append(row)
        conflict = False
        legacy_unverified = False
        for reviews in cases.values():
            # A case is one incident/model, not one analyst. Older decision reviews
            # remain append-only history; only the most recently reviewed decision
            # participates in the current adjudication of that independent case.
            latest = max(
                reviews,
                key=lambda row: (
                    row["decision_recorded_at"], row["recorded_at"], row["rowid"]
                ),
            )
            latest_decision = latest["decision_sha256"]
            verdicts = {
                json.loads(row["payload_json"])["disposition"]
                for row in reviews if row["decision_sha256"] == latest_decision
            }
            if latest_decision == "legacy-unverified":
                dispositions["needs_investigation"] += 1
                legacy_unverified = True
            elif len(verdicts) != 1:
                dispositions["needs_investigation"] += 1
                conflict = True
            else:
                dispositions[next(iter(verdicts))] += 1
        benign_total = dispositions["false_positive"] + dispositions["true_negative"]
        malicious_total = dispositions["false_negative"] + dispositions["true_positive"]
        false_positive_rate = (
            dispositions["false_positive"] / benign_total if benign_total else None
        )
        false_negative_rate = (
            dispositions["false_negative"] / malicious_total if malicious_total else None
        )
        alerts = []
        if conflict:
            alerts.append("FEEDBACK_CONFLICT")
        if legacy_unverified:
            alerts.append("FEEDBACK_LEGACY_UNVERIFIED")
        if benign_total >= 50 and false_positive_rate is not None and false_positive_rate > 0.1:
            alerts.append("FALSE_POSITIVE_RATE_HIGH")
        if (
            malicious_total >= 50
            and false_negative_rate is not None
            and false_negative_rate > 0.05
        ):
            alerts.append("FALSE_NEGATIVE_RATE_HIGH")
        return {
            "feedback_total": len(cases),
            "feedback_by_disposition": dispositions,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
            "quality_alerts": alerts,
        }
