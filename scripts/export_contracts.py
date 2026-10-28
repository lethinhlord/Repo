import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.app.contracts import DecisionRecord, IncidentRequest  # noqa: E402
from api.app.main import app  # noqa: E402

SCHEMA_DIR = ROOT / "schemas"


def write_json(name: str, value: dict) -> None:
    SCHEMA_DIR.mkdir(exist_ok=True)
    (SCHEMA_DIR / name).write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    write_json("incident-request.schema.json", IncidentRequest.model_json_schema())
    write_json("decision-record.schema.json", DecisionRecord.model_json_schema())
    write_json("openapi-v1.json", app.openapi())
