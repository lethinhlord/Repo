#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON_BIN:-.venv-ml/bin/python}"
mkdir -p evidence

"$PYTHON_BIN" scripts/generate_runtime_sbom.py \
  --output evidence/python-runtime.cdx.json
"$PYTHON_BIN" -m pip_audit \
  -r requirements-runtime.lock \
  --disable-pip \
  --format json \
  --output evidence/python-runtime-vulnerability-audit.json

EXPECTED_N8N_DIGEST="sha256:d02752c6ab446ae9db8deec2f9cc887c378f77cdcad31650814df936b7386dfb"
ACTUAL_N8N_DIGEST="$(docker buildx imagetools inspect docker.n8n.io/n8nio/n8n:2.44.6 --format '{{json .Manifest.Digest}}' | tr -d '"')"
test "$ACTUAL_N8N_DIGEST" = "$EXPECTED_N8N_DIGEST"
docker compose config --quiet

printf 'Supply-chain gate passed: hashed Python lock, SBOM, vulnerability audit, pinned image digest.\n'
