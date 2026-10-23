#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-.}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
mkdir -p evidence

"$PYTHON_BIN" scripts/generate_runtime_sbom.py \
  --output evidence/week2-python-runtime.cdx.json

"$PYTHON_BIN" -m pytest > evidence/week2-pytest.log
cat evidence/week2-pytest.log
"$PYTHON_BIN" -m ruff check api ml tests scripts > evidence/week2-ruff.log
cat evidence/week2-ruff.log
docker compose config --quiet
docker compose ps > evidence/week2-compose-ps.log
cat evidence/week2-compose-ps.log
docker compose images --format json > evidence/week2-compose-images.json

curl -fsS http://127.0.0.1:8000/health > evidence/week2-api-health.json
curl -fsS http://127.0.0.1:8000/ready > evidence/week2-api-ready.json
curl -fsS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account.json \
  http://127.0.0.1:8000/features/wazuh \
  > evidence/week2-feature-response.json

attempt=0
while :; do
  webhook_status="$(curl -sS -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' --data '{}' \
    http://127.0.0.1:5678/webhook/wazuh-alert-week2 || true)"
  [ "$webhook_status" = "401" ] && break
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "Week 2 webhook is not registered (last HTTP $webhook_status)" >&2
    exit 1
  fi
  sleep 2
done
set -a
. ./.env
set +a
"$PYTHON_BIN" scripts/send_signed_webhook.py fixtures/wazuh-alert-account.json \
  --url http://127.0.0.1:5678/webhook/wazuh-alert-week2 \
  --output evidence/week2-e2e-response.json
"$PYTHON_BIN" scripts/send_signed_webhook.py fixtures/wazuh-alert-account-benign.json \
  --url http://127.0.0.1:5678/webhook/wazuh-alert-week2 \
  --output evidence/week2-e2e-benign-response.json
"$PYTHON_BIN" scripts/send_signed_webhook.py fixtures/wazuh-alert-malformed.json \
  --url http://127.0.0.1:5678/webhook/wazuh-alert-week2 \
  --expect-http-status 401 \
  --output evidence/week2-e2e-degraded-response.json

"$PYTHON_BIN" - <<'PY'
import json
from pathlib import Path

feature = json.loads(Path("evidence/week2-feature-response.json").read_text())
result = json.loads(Path("evidence/week2-e2e-response.json").read_text())
benign = json.loads(Path("evidence/week2-e2e-benign-response.json").read_text())
degraded = json.loads(Path("evidence/week2-e2e-degraded-response.json").read_text())
assert feature["feature_schema_version"] == "features-v2"
assert feature["quality_status"] == "COMPLETE"
assert result["status"] in {"shadow_notified", "review_notified"}
assert result["automation_state"] == "SHADOW"
assert result["strong_action_allowed"] is False
assert result["notification_status"] in {"SENT", "ALREADY_SENT"}
assert benign["status"] in {"shadow_notified", "review_notified"}
assert benign["strong_action_allowed"] is False
assert degraded["response_code"] == 401
assert degraded["status"] == "unauthorized"
assert degraded["automation_state"] == "SHADOW"
assert degraded["strong_action_allowed"] is False
assert degraded["review_required"] is True
print(json.dumps(result, indent=2, ensure_ascii=False))
PY

curl -fsS http://127.0.0.1:8000/model/metrics \
  > evidence/week2-model-metrics.json

printf 'Week 2 verification completed successfully.\n'
