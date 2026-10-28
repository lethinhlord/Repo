import json
import sqlite3
from pathlib import Path

import pytest

from api.app.contracts import AnalystFeedbackRequest, IncidentRecordRequest
from api.app.feedback_store import AnalystFeedbackStore
from api.app.incident_store import IncidentStore


def stores(tmp_path: Path, predicted_class: str = "malicious"):
    path = tmp_path / "incidents.sqlite3"
    incidents = IncidentStore(path)
    incidents.record(IncidentRecordRequest(
        incident_id="INC-FEEDBACK", source_event_id="E1", route="review",
        review_required=True, notification="review",
        decision={"prediction": {"model_version": "test-model-v1",
                                 "predicted_class": predicted_class}},
    ))
    return incidents, AnalystFeedbackStore(tmp_path / "feedback.sqlite3", path)


def feedback(analyst: str, *, label: str = "benign", disposition: str = "false_positive"):
    return AnalystFeedbackRequest(
        incident_id="INC-FEEDBACK", model_version="test-model-v1",
        analyst_id=analyst, analyst_label=label, disposition=disposition,
    )


def test_feedback_rejects_false_positive_for_a_benign_prediction(tmp_path: Path) -> None:
    _, store = stores(tmp_path, predicted_class="benign")
    with pytest.raises(ValueError, match="predicted_class"):
        store.record(feedback("analyst-1"))


def test_fifty_reviews_of_one_incident_are_one_independent_case(tmp_path: Path) -> None:
    _, store = stores(tmp_path)
    for index in range(50):
        store.record(feedback(f"analyst-{index}"))

    result = store.summary("test-model-v1")
    assert result["feedback_total"] == 1
    assert result["feedback_by_disposition"]["false_positive"] == 1
    assert result["quality_alerts"] == []


def test_conflicting_reviews_remain_unresolved_and_do_not_enter_error_rates(
    tmp_path: Path,
) -> None:
    _, store = stores(tmp_path)
    store.record(feedback("analyst-1"))
    store.record(feedback("analyst-2", label="malicious", disposition="true_positive"))

    result = store.summary("test-model-v1")
    assert result["feedback_total"] == 1
    assert result["feedback_by_disposition"]["needs_investigation"] == 1
    assert result["false_positive_rate"] is None
    assert result["false_negative_rate"] is None
    assert "FEEDBACK_CONFLICT" in result["quality_alerts"]


def test_review_of_updated_prediction_preserves_history_without_double_counting(
    tmp_path: Path,
) -> None:
    incidents, store = stores(tmp_path)
    store.record(feedback("analyst-1"))
    incidents.record(IncidentRecordRequest(
        incident_id="INC-FEEDBACK", source_event_id="E2", route="shadow",
        review_required=False, notification="updated",
        decision={"prediction": {"model_version": "test-model-v1",
                                 "predicted_class": "benign"}},
    ))
    updated = feedback("analyst-1", disposition="true_negative")
    assert store.record(updated).disposition == "created"
    assert store.record(updated).disposition == "duplicate"
    summary = store.summary("test-model-v1")
    assert summary["feedback_total"] == 1
    assert summary["feedback_by_disposition"]["true_negative"] == 1
    assert summary["feedback_by_disposition"]["false_positive"] == 0


def test_late_review_of_an_older_prediction_does_not_replace_newer_adjudication(
    tmp_path: Path, monkeypatch,
) -> None:
    incidents, store = stores(tmp_path)
    old_reference = store._validate_incident_reference(feedback("analyst-old"))
    incidents.record(IncidentRecordRequest(
        incident_id="INC-FEEDBACK", source_event_id="E2", route="shadow",
        review_required=False, notification="updated",
        decision={"prediction": {"model_version": "test-model-v1",
                                 "predicted_class": "benign"}},
    ))
    store.record(feedback("analyst-current", disposition="true_negative"))
    # Model an older request paused after its reference check while E2 was recorded.
    monkeypatch.setattr(store, "_validate_incident_reference", lambda _request: old_reference)
    store.record(feedback("analyst-old"))
    summary = store.summary("test-model-v1")
    assert summary["feedback_total"] == 1
    assert summary["feedback_by_disposition"]["true_negative"] == 1
    assert summary["feedback_by_disposition"]["false_positive"] == 0


def test_legacy_reviews_are_retained_but_not_counted_as_verified_error_samples(
    tmp_path: Path,
) -> None:
    path = tmp_path / "feedback.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE analyst_feedback (feedback_id TEXT PRIMARY KEY,"
            "incident_id TEXT,model_version TEXT,analyst_id TEXT,payload_hash TEXT,"
            "payload_json TEXT,recorded_at TEXT)"
        )
        request = feedback("legacy-analyst")
        connection.execute(
            "INSERT INTO analyst_feedback VALUES (?,?,?,?,?,?,?)",
            ("a"*64, request.incident_id, request.model_version, request.analyst_id,
             "b"*64, request.model_dump_json(), "2026-10-20T00:00:00+00:00"),
        )
    store = AnalystFeedbackStore(path, tmp_path / "incidents.sqlite3")
    result = store.summary("test-model-v1")
    assert result["feedback_total"] == 1
    assert result["feedback_by_disposition"]["needs_investigation"] == 1
    assert result["false_positive_rate"] is None
    assert "FEEDBACK_LEGACY_UNVERIFIED" in result["quality_alerts"]
    with sqlite3.connect(path) as connection:
        original = connection.execute("SELECT payload_json FROM analyst_feedback").fetchone()[0]
    assert json.loads(original) == request.model_dump()


def test_feedback_can_pin_original_event_after_a_new_decision(tmp_path: Path) -> None:
    incidents, store = stores(tmp_path)
    original = feedback("analyst-old").model_copy(update={"source_event_id": "E1"})
    assert store.record(original).disposition == "created"
    incidents.record(IncidentRecordRequest(
        incident_id="INC-FEEDBACK", source_event_id="E2", route="shadow",
        review_required=False, notification="updated",
        decision={"prediction": {"model_version": "test-model-v1",
                                 "predicted_class": "benign"}},
    ))
    store.record(feedback("analyst-current", disposition="true_negative"))
    assert store.record(original).disposition == "duplicate"
    assert store.summary("test-model-v1")["feedback_by_disposition"]["true_negative"] == 1
    with pytest.raises(ValueError, match="source_event_id"):
        store.record(original.model_copy(update={"source_event_id": "unknown"}))
