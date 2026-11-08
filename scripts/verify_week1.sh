#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p evidence

# Runtime images intentionally omit QA tools. Derive QA from the exact API tag.
docker build --build-arg API_IMAGE=datn-ai-soar-api:week1 \
  --tag datn-ai-soar-api:week1-qa --file - . <<'DOCKERFILE'
ARG API_IMAGE
FROM ${API_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends git nodejs \
    && rm -rf /var/lib/apt/lists/*
RUN git config --system --add safe.directory /app
COPY requirements.lock /tmp/requirements-qa.lock
RUN pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements-qa.lock
DOCKERFILE
API_CONTAINER=$(docker compose -p datn-week1 -f compose.week1.yaml --env-file .env.week1 ps -q api)
test -n "$API_CONTAINER" || { echo "Week 1 API container is missing" >&2; exit 1; }
python3 scripts/verify_runtime_artifact.py --runtime-image datn-ai-soar-api:week1 \
  --qa-image datn-ai-soar-api:week1-qa --container "$API_CONTAINER" \
  > evidence/week1-runtime-artifact.json
docker run --rm --mount "type=bind,src=$PWD,dst=/app,readonly" \
  datn-ai-soar-api:week1-qa python -m pytest -q -p no:cacheprovider
docker run --rm --mount "type=bind,src=$PWD,dst=/app,readonly" \
  datn-ai-soar-api:week1-qa python -m ruff check --no-cache api ml tests scripts
docker compose -p datn-week1 -f compose.week1.yaml --env-file .env.week1 config --quiet

curl -fsS http://127.0.0.1:8000/health > evidence/week1-api-health.json
curl -fsS http://127.0.0.1:8000/ready > evidence/week1-api-ready.json
# n8n health can precede registration of the published webhook.
attempt=0
until curl -fsS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account.json \
  http://127.0.0.1:5678/webhook/wazuh-alert > evidence/week1-e2e-response.json; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "Week 1 webhook did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done

docker run --rm -i --mount "type=bind,src=$PWD,dst=/app,readonly" \
  datn-ai-soar-api:week1-qa python - <<'PY'
import json
from pathlib import Path

health = json.loads(Path("evidence/week1-api-health.json").read_text())
assert health["status"] == "ok"
assert health["api_version"] == "4.0.0"
ready = json.loads(Path("evidence/week1-api-ready.json").read_text())
assert ready["inference_mode"] == "mock"
assert ready["model_status"] == "not_configured"
assert ready["ti_mode"] == "mock"
result = json.loads(Path("evidence/week1-e2e-response.json").read_text())
assert result["status"] == "notified"
assert result["automation_state"] == "SHADOW"
assert result["strong_action_allowed"] is False
assert result["decision"]["risk"]["display"] == 8.9
assert result["audit"]["outcome"] == "NOTIFIED"
assert result["decision"]["prediction"]["model_version"] == "mock-v1"
print(json.dumps(result, indent=2, ensure_ascii=False))
PY
