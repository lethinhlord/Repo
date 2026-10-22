import json
from pathlib import Path

from api.app.contracts import (
    AssetContext,
    FeatureBatchResponse,
    FeaturePipelineResponse,
    FeatureStateResponse,
    IncidentRecordRequest,
    IncidentRecordResponse,
    RiskEvaluation,
    RiskEvaluationRequest,
    ThreatIntelligenceResult,
    ThreatLookupRequest,
)
from api.app.main import app

ROOT = Path(__file__).resolve().parents[1]
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
    write_json("asset-context.schema.json", AssetContext.model_json_schema())
    write_json("ti-lookup.schema.json", ThreatLookupRequest.model_json_schema())
    write_json("ti-result.schema.json", ThreatIntelligenceResult.model_json_schema())
    write_json("risk-evaluation-request.schema.json", RiskEvaluationRequest.model_json_schema())
    write_json("risk-evaluation.schema.json", RiskEvaluation.model_json_schema())
    write_json("openapi-week2.json", app.openapi())
