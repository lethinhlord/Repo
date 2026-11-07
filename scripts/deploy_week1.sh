#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

# Keep this historical mock slice separate from the trained deployment's .env.
umask 077
touch .env.week1
chmod 600 .env.week1
for name in N8N_ENCRYPTION_KEY WAZUH_WEBHOOK_SECRET MODEL_PACKAGE_SIGNING_KEY; do
  if ! grep -Eq "^${name}=.+$" .env.week1; then
    # Compose uses the last assignment if an earlier empty assignment exists.
    printf '\n%s=%s\n' "$name" "$(openssl rand -hex 32)" >> .env.week1
  fi
done

compose() {
  docker compose -p datn-week1 -f compose.week1.yaml --env-file .env.week1 "$@"
}

compose config --quiet
./scripts/build_reproducible_image.sh datn-ai-soar-api:week1
compose up -d api
compose run --rm --no-deps n8n \
  import:workflow --input=/workflows/week1-wazuh-mock-ai.json
compose run --rm --no-deps n8n \
  publish:workflow --id=week1WazuhMockAI
compose up -d n8n

attempt=0
until curl -fsS http://127.0.0.1:5678/healthz >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "n8n did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done

compose ps
