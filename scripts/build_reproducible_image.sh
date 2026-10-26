#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

IMAGE_TAG="datn-ai-soar-api:week3"
OUTPUT_PATH=""
NO_CACHE=""
IMAGE_SET=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-cache)
      NO_CACHE="--no-cache"
      ;;
    --output)
      [ "$#" -ge 2 ] || { echo "--output requires a path" >&2; exit 2; }
      OUTPUT_PATH="$2"
      shift
      ;;
    --help)
      echo "Usage: $0 [--no-cache] [--output OCI_TAR] [IMAGE_TAG]"
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
    *)
      [ "$IMAGE_SET" = false ] || { echo "Only one image tag is allowed" >&2; exit 2; }
      IMAGE_TAG="$1"
      IMAGE_SET=true
      ;;
  esac
  shift
done

if [ -n "$(git status --porcelain --untracked-files=all -- \
  api ml config requirements-runtime.lock .dockerignore)" ]; then
  echo "Reproducible image inputs differ from HEAD; commit or remove them first." >&2
  exit 1
fi

SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
test -n "$SOURCE_DATE_EPOCH"

TEMP_DIR=""
if [ -z "$OUTPUT_PATH" ]; then
  TEMP_DIR="$(mktemp -d)"
  OUTPUT_PATH="$TEMP_DIR/image.oci.tar"
  trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
else
  test ! -e "$OUTPUT_PATH" || {
    echo "Output already exists: $OUTPUT_PATH" >&2
    exit 1
  }
fi

docker buildx build $NO_CACHE \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --provenance=false \
  --sbom=false \
  --output "type=oci,dest=$OUTPUT_PATH,name=$IMAGE_TAG,rewrite-timestamp=true" \
  --file api/Dockerfile \
  .

MANIFEST_DIGEST="$(tar -xOf "$OUTPUT_PATH" index.json | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])')"
printf 'Reproducible OCI manifest: %s\n' "$MANIFEST_DIGEST"

if [ -n "$TEMP_DIR" ]; then
  docker load --input "$OUTPUT_PATH"
  docker image inspect "$IMAGE_TAG" >/dev/null
  printf 'Loaded image: %s\n' "$IMAGE_TAG"
else
  printf 'OCI archive: %s\n' "$OUTPUT_PATH"
fi
