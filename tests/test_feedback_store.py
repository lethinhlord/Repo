from pathlib import Path

from api.app.contracts import AnalystFeedbackRequest, IncidentRecordRequest
from api.app.feedback_store import AnalystFeedbackStore
from api.app.incident_store import IncidentStore


def test_feedback_summary_raises_quality_alert_after_minimum_adjudications(
    tmp_path: Path,
) -> None:
    incident_path = tmp_path / "incidents.sqlite3"
    feedback_path = tmp_path / "feedback.sqlite3"
    incidents = IncidentStore(incident_path)
    feedback = AnalystFeedbackStore(feedback_path, incident_path)

    for index in range(50):
        incident_id = f"INC-FP-{index:03d}"
        incidents.record(
            IncidentRecordRequest(
                incident_id=incident_id,
                source_event_id=f"EVENT-FP-{index:03d}",
                route="review",
                review_required=True,
                notification="manual review required",
                decision={
                    "prediction": {
                        "model_version": "test-model-v1",
                        "family": "account",
                    }
                },
            )
        )
        feedback.record(
            AnalystFeedbackRequest(
                incident_id=incident_id,
                model_version="test-model-v1",
                analyst_id="soc-analyst-01",
                analyst_label="benign",
                disposition="false_positive",
            )
        )

    summary = feedback.summary("test-model-v1")

    assert summary["feedback_total"] == 50
    assert summary["feedback_by_disposition"]["false_positive"] == 50
    assert summary["false_positive_rate"] == 1.0
    assert summary["false_negative_rate"] is None
    assert summary["quality_alerts"] == ["FALSE_POSITIVE_RATE_HIGH"]
