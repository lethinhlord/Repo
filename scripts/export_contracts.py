import json
from pathlib import Path

from api.app.contracts import DecisionRecord, IncidentRequest
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
    write_json("incident-request.schema.json", IncidentRequest.model_json_schema())
    write_json("decision-record.schema.json", DecisionRecord.model_json_schema())
    write_json("openapi-v1.json", app.openapi())
