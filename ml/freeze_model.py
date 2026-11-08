from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import uuid
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


def _verification_key(key_id: str) -> bytes:
    current = _signing_key()
    try:
        previous = json.loads(os.getenv("MODEL_PACKAGE_VERIFICATION_KEYS", "[]"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid model package verification keyring") from exc
    if not isinstance(previous, list) or any(
        not isinstance(key, str) or len(key.encode()) < 32 for key in previous
    ):
        raise ValueError("model package verification keys must be a JSON list of strong keys")
    for key in [current, *(key.encode() for key in previous)]:
        if hashlib.sha256(key).hexdigest()[:16] == key_id:
            return key
    raise ValueError("model package signing key identifier does not match trusted keyring")


def sign_evidence(document: dict[str, object]) -> dict[str, object]:
    key = _signing_key()
    signed = {**document, "signing_key_id": hashlib.sha256(key).hexdigest()[:16]}
    signed["signature_hmac_sha256"] = _signature(signed, key)
    return signed


def verify_evidence(document: dict[str, object]) -> None:
    unsigned = dict(document)
    signature = unsigned.pop("signature_hmac_sha256", "")
    key = _verification_key(str(unsigned.get("signing_key_id", "")))
    if (not isinstance(signature, str)
            or not hmac.compare_digest(signature, _signature(unsigned, key))):
        raise ValueError("evaluation evidence signature integrity failed")


def verify_frozen_manifest(package_dir: Path) -> dict[str, object]:
    try:
        freeze = json.loads((package_dir / "FROZEN.json").read_text(encoding="utf-8"))
        signature = str(freeze.pop("signature_hmac_sha256"))
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError("invalid signed frozen manifest") from exc
    signing_key = _verification_key(str(freeze.get("signing_key_id", "")))
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
    if (package_dir / "FROZEN.json").exists() or (package_dir / "FROZEN.json").is_symlink():
        # Repeating freeze validates the original trust boundary, never signs new content.
        result = verify_frozen_manifest(package_dir)
        from ml.evaluation_registry import registry_status
        registry_status(package_dir)
        return result
    if any((package_dir / name).exists() or (package_dir / name).is_symlink() for name in (
        "LOCKED_TEST_RESERVED", "LOCKED_TEST_OPENED.json", "metrics_locked_test.json",
        "CHALLENGE_RESERVED", "challenge_evaluation.json",
    )):
        raise ValueError("cannot freeze a package with pre-existing test opening evidence")
    missing = [name for name in PACKAGE_FILES if not (package_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(f"cannot freeze incomplete package; missing: {missing}")
    metadata = json.loads((package_dir / "metadata.json").read_text(encoding="utf-8"))
    if metadata.get("locked_test_status") != "UNOPENED":
        raise ValueError("package must be frozen before the locked test is opened")
    signing_key = _signing_key()
    result = {
        "format_version": "model-package-v3",
        "evaluation_registry_id": uuid.uuid4().hex,
        "model_version": metadata["model_version"],
        "signing_key_id": hashlib.sha256(signing_key).hexdigest()[:16],
        "frozen_at_utc": datetime.now(UTC).isoformat(),
        "files_sha256": {name: file_hash(package_dir / name) for name in PACKAGE_FILES},
    }
    result["signature_hmac_sha256"] = _signature(result, signing_key)
    with (package_dir / "FROZEN.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    from ml.evaluation_registry import initialize_registry
    initialize_registry(package_dir)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze a selected model package")
    parser.add_argument("--package-dir", type=Path, default=Path("ml/model-package"))
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify the signed immutable package without modifying it",
    )
    parser.add_argument("--migrate-legacy-registry", type=Path, metavar="SIGNED_RECEIPT")
    parser.add_argument("--receipt-archive", type=Path)
    args = parser.parse_args()
    if args.migrate_legacy_registry:
        if args.receipt_archive is None or args.verify_only:
            parser.error("migration requires --receipt-archive and cannot use --verify-only")
        from ml.evaluation_registry import migrate_legacy_registry
        migrate_legacy_registry(
            args.package_dir, args.migrate_legacy_registry, args.receipt_archive,
        )
        print("Legacy evaluation registry initialized from verified migration provenance")
    elif args.verify_only:
        result = verify_frozen_manifest(args.package_dir)
        from ml.evaluation_registry import registry_status
        registry_status(args.package_dir)
        print(f"Verified model package: {result['model_version']}")
    else:
        result = freeze(args.package_dir)
        print(f"Frozen model package: {result['model_version']}")


if __name__ == "__main__":
    main()
