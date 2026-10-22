#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p evidence

docker run --rm --mount "type=bind,src=$PWD,dst=/app" \
  datn-ai-soar-api:week2 python -m pytest > evidence/week2-pytest.log
cat evidence/week2-pytest.log
docker run --rm --mount "type=bind,src=$PWD,dst=/app" \
  datn-ai-soar-api:week2 ruff check api ml tests scripts > evidence/week2-ruff.log
cat evidence/week2-ruff.log
docker compose config --quiet
docker compose ps > evidence/week2-compose-ps.log
cat evidence/week2-compose-ps.log

curl -fsS http://127.0.0.1:8000/health > evidence/week2-api-health.json
curl -fsS http://127.0.0.1:8000/ready > evidence/week2-api-ready.json
curl -fsS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account.json \
  http://127.0.0.1:8000/features/wazuh \
  > evidence/week2-feature-response.json
curl -fsS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account.json \
  http://127.0.0.1:5678/webhook/wazuh-alert-week2 \
  > evidence/week2-e2e-response.json
curl -fsS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account-benign.json \
  http://127.0.0.1:5678/webhook/wazuh-alert-week2 \
  > evidence/week2-e2e-benign-response.json
curl -fsS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-malformed.json \
  http://127.0.0.1:5678/webhook/wazuh-alert-week2 \
  > evidence/week2-e2e-degraded-response.json

python3 - <<'PY'
import json
from pathlib import Path

feature = json.loads(Path("evidence/week2-feature-response.json").read_text())
result = json.loads(Path("evidence/week2-e2e-response.json").read_text())
benign = json.loads(Path("evidence/week2-e2e-benign-response.json").read_text())
degraded = json.loads(Path("evidence/week2-e2e-degraded-response.json").read_text())
assert feature["feature_schema_version"] == "features-v2"
assert feature["quality_status"] == "COMPLETE"
assert result["status"] == "notified"
assert result["automation_state"] == "SHADOW"
assert result["strong_action_allowed"] is False
assert result["decision"]["audit"]["workflow_revision"] == "week2-shadow-v1"
assert benign["status"] == "notified"
assert benign["decision"]["prediction"]["predicted_class"] == "benign"
assert benign["strong_action_allowed"] is False
assert degraded["status"] == "review_required"
assert degraded["automation_state"] == "SHADOW"
assert degraded["strong_action_allowed"] is False
assert degraded["review_required"] is True
print(json.dumps(result, indent=2, ensure_ascii=False))
PY

printf 'Week 2 verification completed successfully.\n'
