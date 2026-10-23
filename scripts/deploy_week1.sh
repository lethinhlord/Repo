#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  umask 077
  printf 'N8N_ENCRYPTION_KEY=%s\nN8N_PUBLIC_HOST=%s\n' \
    "$(openssl rand -hex 32)" "${N8N_PUBLIC_HOST:-192.168.149.128}" > .env
fi

docker compose down
./scripts/build_reproducible_image.sh datn-ai-soar-api:week3
docker compose up -d api
docker compose run --rm --no-deps n8n \
  import:workflow --input=/workflows/week1-wazuh-mock-ai.json
docker compose run --rm --no-deps n8n \
  publish:workflow --id=week1WazuhMockAI
docker compose up -d n8n

attempt=0
until curl -fsS http://localhost:5678/healthz >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "n8n did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done

docker compose ps
