#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  umask 077
  printf 'N8N_ENCRYPTION_KEY=%s\nWAZUH_WEBHOOK_SECRET=%s\nN8N_PUBLIC_HOST=%s\nVT_MODE=mock\nVT_API_KEY=\nVT_TIMEOUT_SECONDS=5\n' \
    "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" \
    "${N8N_PUBLIC_HOST:-192.168.149.128}" > .env
fi

if ! grep -q '^VT_MODE=' .env; then
  printf '\nVT_MODE=mock\nVT_API_KEY=\nVT_TIMEOUT_SECONDS=5\n' >> .env
fi
if ! grep -q '^WAZUH_WEBHOOK_SECRET=' .env; then
  printf 'WAZUH_WEBHOOK_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env
fi

docker compose config --quiet
docker compose down --remove-orphans
docker compose --progress plain build api
docker compose up -d api

attempt=0
until curl -fsS http://127.0.0.1:8000/ready >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "Week 2 API did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done

docker compose run --rm --no-deps n8n \
  import:workflow --input=/workflows/week2-feature-ti-asset-shadow.json
docker compose run --rm --no-deps n8n \
  publish:workflow --id=week2FeatureTiAssetShadow
docker compose up -d n8n

attempt=0
until curl -fsS http://127.0.0.1:5678/healthz >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "n8n did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done

docker compose ps
curl -fsS http://127.0.0.1:8000/ready | python3 -c \
  'import json,sys; data=json.load(sys.stdin); assert data["status"] == "ready"; print(json.dumps(data, indent=2))'
printf '\nWeek 2 deployment is ready in SHADOW mode.\n'
