from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from pathlib import Path

PACKAGE_FILES = (
    "model.joblib",
    "thresholds.json",
    "metadata.json",
    "metrics_validation.json",
    "eda_train.json",
    "leakage_audit.json",
    "calibration_validation.json",
    "feature_profile.json",
    "feature_schema.json",
)


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _signing_key() -> bytes:
    key = os.getenv("MODEL_PACKAGE_SIGNING_KEY", "").encode()
    if len(key) < 32:
        raise ValueError("MODEL_PACKAGE_SIGNING_KEY must contain at least 32 bytes")
    return key


def _signature(document: dict[str, object], key: bytes) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_frozen_manifest(package_dir: Path) -> dict[str, object]:
    try:
        freeze = json.loads((package_dir / "FROZEN.json").read_text(encoding="utf-8"))
        signature = str(freeze.pop("signature_hmac_sha256"))
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError("invalid signed frozen manifest") from exc
    signing_key = _signing_key()
    expected_key_id = hashlib.sha256(signing_key).hexdigest()[:16]
    if freeze.get("signing_key_id") != expected_key_id:
        raise ValueError("model package signing key identifier does not match")
    if not hmac.compare_digest(signature, _signature(freeze, signing_key)):
        raise ValueError("frozen manifest signature verification failed")
    if freeze.get("format_version") != "model-package-v3":
        raise ValueError("unsupported frozen model package format")
    hashes = freeze.get("files_sha256")
    if not isinstance(hashes, dict):
        raise ValueError("frozen manifest file hashes are missing")
    for name in PACKAGE_FILES:
        if hashes.get(name) != file_hash(package_dir / name):
            raise ValueError(f"model package integrity verification failed: {name}")
    freeze["signature_hmac_sha256"] = signature
    return freeze


def freeze(package_dir: Path) -> dict[str, object]:
    missing = [name for name in PACKAGE_FILES if not (package_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(f"cannot freeze incomplete package; missing: {missing}")
    metadata = json.loads((package_dir / "metadata.json").read_text(encoding="utf-8"))
    if metadata.get("locked_test_status") != "UNOPENED":
        raise ValueError("package must be frozen before the locked test is opened")
    signing_key = _signing_key()
    result = {
        "format_version": "model-package-v3",
        "model_version": metadata["model_version"],
        "signing_key_id": hashlib.sha256(signing_key).hexdigest()[:16],
        "frozen_at_utc": datetime.now(UTC).isoformat(),
        "files_sha256": {name: file_hash(package_dir / name) for name in PACKAGE_FILES},
    }
    result["signature_hmac_sha256"] = _signature(result, signing_key)
    (package_dir / "FROZEN.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze a selected model package")
    parser.add_argument("--package-dir", type=Path, default=Path("ml/model-package"))
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify the signed immutable package without modifying it",
    )
    args = parser.parse_args()
    if args.verify_only:
        result = verify_frozen_manifest(args.package_dir)
        print(f"Verified model package: {result['model_version']}")
    else:
        result = freeze(args.package_dir)
        print(f"Frozen model package: {result['model_version']}")


if __name__ == "__main__":
    main()
