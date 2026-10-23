from __future__ import annotations

import hashlib
import json
import sqlite3
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

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
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
                """
            )

    def _validate_incident_reference(self, request: AnalystFeedbackRequest) -> None:
        if not self.incident_path.is_file():
            raise ValueError("incident ledger is unavailable; feedback cannot be orphaned")
        with sqlite3.connect(self.incident_path, timeout=10) as connection:
            row = connection.execute(
                "SELECT payload_json FROM incidents WHERE incident_id = ?",
                (request.incident_id,),
            ).fetchone()
        if row is None:
            raise ValueError("feedback references an unknown incident")
        try:
            payload = json.loads(row[0])
            model_version = payload["decision"]["prediction"]["model_version"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("incident does not contain a traceable model decision") from exc
        if model_version != request.model_version:
            raise ValueError("feedback model_version does not match the incident decision")

    @staticmethod
    def _identity(request: AnalystFeedbackRequest) -> str:
        identity = "\x1f".join(
            (request.incident_id, request.model_version, request.analyst_id)
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
        self._validate_incident_reference(request)
        feedback_id = self._identity(request)
        payload, payload_hash = self._payload(request)
        now = datetime.now(UTC)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload_hash, recorded_at FROM analyst_feedback "
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
                "INSERT INTO analyst_feedback VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    feedback_id,
                    request.incident_id,
                    request.model_version,
                    request.analyst_id,
                    payload_hash,
                    payload,
                    now.isoformat(),
                ),
            )
        return AnalystFeedbackResponse(
            feedback_id=feedback_id,
            incident_id=request.incident_id,
            model_version=request.model_version,
            disposition="created",
            recorded_at=now,
        )
