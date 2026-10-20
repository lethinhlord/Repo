from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from ml.freeze_model import PACKAGE_FILES, file_hash
from ml.metrics import classification_metrics


def evaluate_locked_test(
    package_dir: Path,
    locked_test_path: Path,
    *,
    unlock_locked_test: bool,
) -> dict[str, Any]:
    if not unlock_locked_test:
        raise PermissionError(
            "locked test access denied; pass --unlock-locked-test only after the Week 6 freeze gate"
        )
    freeze_path = package_dir / "FROZEN.json"
    if not freeze_path.is_file():
        raise PermissionError("model package must be frozen before opening the locked test")
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    for name in PACKAGE_FILES:
        if file_hash(package_dir / name) != freeze["files_sha256"][name]:
            raise PermissionError(f"frozen package integrity check failed: {name}")
    bundle = joblib.load(package_dir / "model.joblib")
    rows = [
        json.loads(line)
        for line in locked_test_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    output: dict[str, Any] = {"model_version": freeze["model_version"], "families": {}}
    for family, artifact in bundle["families"].items():
        subset = [row for row in rows if row["family"] == family]
        if not subset:
            raise ValueError(f"locked test has no records for family {family}")
        x = np.asarray(
            [[row["features"][name] for name in artifact["feature_order"]] for row in subset]
        )
        labels = np.asarray([row["label"] for row in subset], dtype=int)
        probabilities = artifact["estimator"].predict_proba(x)[:, 1]
        output["families"][family] = classification_metrics(
            labels, probabilities, float(artifact["threshold"])
        )
    path = package_dir / "metrics_locked_test.json"
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the immutable model on locked test data")
    parser.add_argument("--package-dir", type=Path, default=Path("ml/model-package"))
    parser.add_argument(
        "--locked-test", type=Path, default=Path("data/processed/locked_test.jsonl")
    )
    parser.add_argument("--unlock-locked-test", action="store_true")
    args = parser.parse_args()
    result = evaluate_locked_test(
        args.package_dir,
        args.locked_test,
        unlock_locked_test=args.unlock_locked_test,
    )
    print(f"Locked-test evaluation complete for {result['model_version']}")


if __name__ == "__main__":
    main()
