#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
IMAGE_TAG="datn-ai-soar-api:reproducibility-check"

./scripts/build_reproducible_image.sh --no-cache \
  --output "$TEMP_DIR/first.oci.tar" "$IMAGE_TAG"
./scripts/build_reproducible_image.sh --no-cache \
  --output "$TEMP_DIR/second.oci.tar" "$IMAGE_TAG"

manifest_digest() {
  tar -xOf "$1" index.json | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])'
}

FIRST_DIGEST="$(manifest_digest "$TEMP_DIR/first.oci.tar")"
SECOND_DIGEST="$(manifest_digest "$TEMP_DIR/second.oci.tar")"
test "$FIRST_DIGEST" = "$SECOND_DIGEST"

printf 'Reproducible image gate passed: %s\n' "$FIRST_DIGEST"
