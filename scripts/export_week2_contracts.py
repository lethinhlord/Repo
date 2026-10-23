import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.app.contracts import (  # noqa: E402 - repository root is bootstrapped above
    AnalystFeedbackRequest,
    AnalystFeedbackResponse,
    AssetContext,
    FeatureBatchResponse,
    FeaturePipelineResponse,
    FeatureStateResponse,
    IncidentRecordRequest,
    IncidentRecordResponse,
    ModelMetricsResponse,
    NotificationDispatchRequest,
    NotificationDispatchResponse,
    RiskEvaluation,
    RiskEvaluationRequest,
    SignedWazuhIngestRequest,
    SignedWazuhIngestResponse,
    ThreatIntelligenceResult,
    ThreatLookupRequest,
)
from api.app.main import app  # noqa: E402 - repository root is bootstrapped above

SCHEMA_DIR = ROOT / "schemas"


def write_json(name: str, value: dict) -> None:
    SCHEMA_DIR.mkdir(exist_ok=True)
    (SCHEMA_DIR / name).write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    write_json(
        "feature-pipeline-response.schema.json",
        FeaturePipelineResponse.model_json_schema(),
    )
    write_json("feature-batch-response.schema.json", FeatureBatchResponse.model_json_schema())
    write_json("feature-state-response.schema.json", FeatureStateResponse.model_json_schema())
    write_json("incident-record-request.schema.json", IncidentRecordRequest.model_json_schema())
    write_json("incident-record-response.schema.json", IncidentRecordResponse.model_json_schema())
    write_json("signed-ingest-request.schema.json", SignedWazuhIngestRequest.model_json_schema())
    write_json("signed-ingest-response.schema.json", SignedWazuhIngestResponse.model_json_schema())
    write_json("model-metrics.schema.json", ModelMetricsResponse.model_json_schema())
    write_json("model-feedback-request.schema.json", AnalystFeedbackRequest.model_json_schema())
    write_json("model-feedback-response.schema.json", AnalystFeedbackResponse.model_json_schema())
    write_json(
        "notification-dispatch-request.schema.json",
        NotificationDispatchRequest.model_json_schema(),
    )
    write_json(
        "notification-dispatch-response.schema.json",
        NotificationDispatchResponse.model_json_schema(),
    )
    write_json("asset-context.schema.json", AssetContext.model_json_schema())
    write_json("ti-lookup.schema.json", ThreatLookupRequest.model_json_schema())
    write_json("ti-result.schema.json", ThreatIntelligenceResult.model_json_schema())
    write_json("risk-evaluation-request.schema.json", RiskEvaluationRequest.model_json_schema())
    write_json("risk-evaluation.schema.json", RiskEvaluation.model_json_schema())
    write_json("openapi-week2.json", app.openapi())
