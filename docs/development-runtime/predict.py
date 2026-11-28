"""Offline development inference; load only an owner-authenticated model archive."""

import argparse
import hashlib
import io
import json
import math
import re
import sys
import tarfile
from pathlib import Path

import joblib
import numpy as np

FILES = {
    "development-model/development_model.joblib",
    "development-model/metadata.json",
    "development-model/feature_schema.json",
    "development-model/metrics_development.json",
    "development-model/eda_train.json",
    "evidence/development-experiment-summary.json",
    "evidence/development-training.log",
}
LIMIT = 32 * 1024 * 1024


def load_archive(path, expected_sha256):
    """Hash the exact compressed bytes before any pickle deserialization."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("Expected SHA-256 must contain 64 hexadecimal characters")
    with Path(path).open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
        raise ValueError("Archive SHA-256 mismatch or archive exceeds 32 MiB")
    contents, directories, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            if member.isdir() and member.name in {"development-model", "evidence"}:
                if member.name in directories or member.size:
                    raise ValueError("Duplicate or invalid archive directory")
                directories.add(member.name)
                continue
            if not member.isfile() or member.name not in FILES or member.name in contents:
                raise ValueError("Unexpected, duplicate or unsafe archive member")
            total += member.size
            if member.size < 0 or total > 2 * LIMIT:
                raise ValueError("Expanded archive exceeds 64 MiB")
            contents[member.name] = archive.extractfile(member).read()
    if set(contents) != FILES:
        raise ValueError("Incomplete model archive")
    metadata = json.loads(contents["development-model/metadata.json"])
    if metadata.get("artifact_kind") != "development-model-v1" or any(
        metadata.get(flag) is not False for flag in ("deployment_eligible", "automation_eligible")
    ):
        raise ValueError("Only an offline development artifact with eligibility false is supported")
    schema = json.loads(contents["development-model/feature_schema.json"])
    metrics = json.loads(contents["development-model/metrics_development.json"])
    payload = joblib.load(io.BytesIO(contents["development-model/development_model.joblib"]))
    if (
        payload.get("metadata") != metadata
        or payload.get("artifact_kind") != metadata["artifact_kind"]
    ):
        raise ValueError("Model metadata differs from archive metadata")
    if schema.get("version") != metadata.get("feature_schema_version"):
        raise ValueError("Model schema version mismatch")
    if set(payload["families"]) != {"account", "c2"}:
        raise ValueError("Expected both account and c2 families")
    for family, model in payload["families"].items():
        estimator = model["estimator"]
        order = schema["x-family-features"][family]
        threshold = model["development_threshold"]
        record = metrics["families"][family]
        if (
            model["feature_order"] != order or len(order) != len(set(order))
            or not set(order) <= set(schema["properties"])
            or not np.array_equal(estimator.classes_, [0, 1])
            or estimator.n_features_in_ != len(order)
            or type(threshold) not in (int, float) or not math.isfinite(threshold)
            or not 0 <= threshold <= 1
            or threshold != record["threshold_selection"]["threshold"]
            or model["model_name"] != record["selected_model"]
        ):
            raise ValueError(f"Inconsistent model contract for {family}")
    return payload, schema


def predict_records(payload, schema, rows):
    """Keep the saved calibration wrapper and family-specific column order."""
    if not rows or len(rows) > 4096:
        raise ValueError("Provide 1 to 4096 JSONL records")
    output = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("family") not in payload["families"]:
            raise ValueError(f"Record {index}: unknown family")
        family = row["family"]
        model, features = payload["families"][family], row.get("features")
        if not isinstance(features, dict) or (
            not set(model["feature_order"]) <= set(features)
            or not set(features) <= set(schema["properties"])
        ):
            raise ValueError(f"Record {index}: missing or unknown feature")
        for key, value in features.items():
            rule = schema["properties"][key]
            if (
                type(value) not in (int, float) or not math.isfinite(value)
                or value < rule.get("minimum", -math.inf)
                or value > rule.get("maximum", math.inf)
                or rule.get("type") == "integer" and value != int(value)
            ):
                raise ValueError(f"Record {index}: invalid feature {key}")
        matrix = np.array([[features[key] for key in model["feature_order"]]], dtype=float)
        probabilities = np.asarray(model["estimator"].predict_proba(matrix))
        if (
            probabilities.shape != (1, 2) or not np.isfinite(probabilities).all()
            or not ((probabilities >= 0) & (probabilities <= 1)).all()
            or not np.allclose(probabilities.sum(axis=1), 1, atol=1e-12, rtol=0)
        ):
            raise ValueError(f"Record {index}: invalid predicted probabilities")
        probability = float(probabilities[0, 1])
        output.append(dict(
            index=index, run_id=row.get("run_id"), family=family,
            probability_malicious=probability,
            development_threshold=model["development_threshold"],
            development_prediction=int(probability >= model["development_threshold"]),
            automation_eligible=False, deployment_eligible=False,
        ))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--records", type=Path, required=True)
    args = parser.parse_args()
    payload, schema = load_archive(args.archive, args.sha256)
    with args.records.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Records exceed 32 MiB")
    rows = [json.loads(line) for line in raw.decode("utf-8-sig").splitlines() if line.strip()]
    predictions = predict_records(payload, schema, rows)
    print(json.dumps(dict(
        status="DEVELOPMENT_INFERENCE_COMPLETE", model_version=payload["metadata"]["model_version"],
        archive_sha256=args.sha256.lower(), records_sha256=hashlib.sha256(raw).hexdigest(),
        record_count=len(predictions), scope="OFFLINE_DEVELOPMENT_INFERENCE_ONLY",
        automation_eligible=False, deployment_eligible=False, predictions=predictions,
    ), allow_nan=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Development inference failed: {error}", file=sys.stderr)
        sys.exit(1)
