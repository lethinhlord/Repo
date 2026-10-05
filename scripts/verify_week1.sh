#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p evidence

docker run --rm --mount "type=bind,src=$PWD,dst=/app" \
  datn-ai-soar-api:week1 python -m pytest -q
docker run --rm --mount "type=bind,src=$PWD,dst=/app" \
  datn-ai-soar-api:week1 ruff check api tests scripts
docker compose config --quiet

curl -fsS http://localhost:8000/health > evidence/week1-api-health.json
curl -fsS -H 'Content-Type: application/json' \
  --data-binary @fixtures/wazuh-alert-account.json \
  http://localhost:5678/webhook/wazuh-alert \
  > evidence/week1-e2e-response.json

python3 - <<'PY'
import json
from pathlib import Path

result = json.loads(Path("evidence/week1-e2e-response.json").read_text())
assert result["status"] == "notified"
assert result["automation_state"] == "SHADOW"
assert result["strong_action_allowed"] is False
assert result["decision"]["risk"]["display"] == 8.9
assert result["audit"]["outcome"] == "NOTIFIED"
print(json.dumps(result, indent=2, ensure_ascii=False))
PY
