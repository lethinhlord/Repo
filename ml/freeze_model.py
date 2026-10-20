from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

PACKAGE_FILES = ("model.joblib", "thresholds.json", "metadata.json", "metrics_validation.json")


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def freeze(package_dir: Path) -> dict[str, object]:
    missing = [name for name in PACKAGE_FILES if not (package_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(f"cannot freeze incomplete package; missing: {missing}")
    metadata = json.loads((package_dir / "metadata.json").read_text(encoding="utf-8"))
    if metadata.get("locked_test_status") != "UNOPENED":
        raise ValueError("package must be frozen before the locked test is opened")
    result = {
        "model_version": metadata["model_version"],
        "frozen_at_utc": datetime.now(UTC).isoformat(),
        "files_sha256": {name: file_hash(package_dir / name) for name in PACKAGE_FILES},
    }
    (package_dir / "FROZEN.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze a selected model package")
    parser.add_argument("--package-dir", type=Path, default=Path("ml/model-package"))
    args = parser.parse_args()
    result = freeze(args.package_dir)
    print(f"Frozen model package: {result['model_version']}")


if __name__ == "__main__":
    main()
