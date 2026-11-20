"""Ingestion boundary tests; synthetic data is never collection evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from test_training_integrity import ROOT, prepare_dataset

from ml import training


def _v3_manifest(tmp_path: Path) -> tuple[Path, dict]:
    config_path, manifest = prepare_dataset(tmp_path)
    manifest["manifest_version"] = "dataset-manifest-v3"
    path = tmp_path / "processed/dataset_manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return config_path, manifest


def test_v3_is_verified_before_partition_access_and_bound_to_both_partitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, manifest = _v3_manifest(tmp_path)
    (tmp_path / "processed/locked_test.jsonl").unlink()
    expected_rows = {
        name: [json.loads(line) for line in (tmp_path / f"processed/{name}.jsonl")
               .read_text(encoding="utf-8").splitlines()]
        for name in ("train", "validation")
    }
    phases = []

    def verify(value, rows_by_partition=None, *, root=None, expected_commit=None):
        assert value == manifest
        assert root == ROOT
        assert expected_commit == manifest["provenance"]["builder_git_commit"]
        if rows_by_partition is None:
            phases.append("metadata")
        else:
            assert phases == ["metadata"]
            assert rows_by_partition == expected_rows
            phases.append("records")

    monkeypatch.setattr(training, "verify_training_manifest", verify, raising=False)
    train_rows, validation_rows, checked = training.verify_training_partitions(
        tmp_path / "processed", ROOT / "ml/feature_schema.json",
        require_collection_audit=False, config_path=config_path,
        expected_commit=manifest["provenance"]["builder_git_commit"],
    )

    assert phases == ["metadata", "records"]
    assert (train_rows, validation_rows) == (expected_rows["train"], expected_rows["validation"])
    assert checked == manifest


def test_v3_metadata_rejection_never_opens_training_or_locked_partitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _v3_manifest(tmp_path)
    for name in ("train", "validation", "locked_test"):
        (tmp_path / f"processed/{name}.jsonl").unlink()

    def reject(*args, **kwargs):
        raise ValueError("reviewed source certificate rejected")

    monkeypatch.setattr(training, "verify_training_manifest", reject, raising=False)
    with pytest.raises(ValueError, match="reviewed source certificate rejected"):
        training.verify_training_partitions(
            tmp_path / "processed", ROOT / "ml/feature_schema.json",
            require_collection_audit=False,
        )


def test_v3_record_binding_rejects_rehashed_partition_before_training(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, manifest = _v3_manifest(tmp_path)
    partition = tmp_path / "processed/train.jsonl"
    rows = [json.loads(line) for line in partition.read_text(encoding="utf-8").splitlines()]
    original_incident = rows[0]["incident_id"]
    rows[0]["incident_id"] = "SYNTHETIC-UNAPPROVED-RECORD"
    partition.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    manifest["partitions"]["train"]["sha256"] = hashlib.sha256(partition.read_bytes()).hexdigest()
    (tmp_path / "processed/dataset_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )

    def verify(value, rows_by_partition=None, **kwargs):
        if (rows_by_partition is not None
            and rows_by_partition["train"][0]["incident_id"] != original_incident):
            raise ValueError("approved record commitment differs")

    def no_training(*args, **kwargs):
        pytest.fail("model training must not start before reviewed records are verified")

    monkeypatch.setattr(training, "verify_training_manifest", verify, raising=False)
    monkeypatch.setattr(training, "build_candidates", no_training)
    with pytest.raises(ValueError, match="approved record commitment differs"):
        training.train(config_path)


def test_v2_keeps_legacy_integrity_checks_without_a_v3_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, manifest = prepare_dataset(tmp_path)

    phases = []

    def verify(value, rows_by_partition=None, **kwargs):
        assert value["manifest_version"] == "dataset-manifest-v2"
        assert "source_compatibility" not in value.get("collection_audit", {})
        phases.append("metadata" if rows_by_partition is None else "records")

    monkeypatch.setattr(training, "verify_training_manifest", verify, raising=False)
    train_rows, validation_rows, checked = training.verify_training_partitions(
        tmp_path / "processed", ROOT / "ml/feature_schema.json",
        require_collection_audit=False, config_path=config_path,
        expected_commit=manifest["provenance"]["builder_git_commit"],
    )
    assert train_rows and validation_rows
    assert checked["manifest_version"] == "dataset-manifest-v2"
    assert phases == ["metadata", "records"]


def test_model_package_retains_the_verified_source_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use the existing tiny synthetic benchmark, never reviewed lab records."""
    config_path, manifest = _v3_manifest(tmp_path)
    certificate = {"review_id": "SYNTHETIC-NOT-LAB"}
    manifest.setdefault("collection_audit", {})["source_compatibility"] = certificate
    manifest["provenance"]["source_compatibility_sha256"] = hashlib.sha256(
        json.dumps(certificate, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()
    (tmp_path / "processed/dataset_manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    (tmp_path / "processed/locked_test.jsonl").unlink()

    def verify(value, rows_by_partition=None, **kwargs):
        assert value["collection_audit"]["source_compatibility"] == certificate

    monkeypatch.setattr(training, "verify_training_manifest", verify)
    metadata = training.train(config_path)
    written = json.loads((tmp_path / "ml/model-package/metadata.json").read_text(encoding="utf-8"))
    assert metadata["dataset_source_compatibility"] == certificate
    assert written["dataset_source_compatibility"] == certificate
    assert written["dataset_provenance"] == manifest["provenance"]
    assert written["locked_test_status"] == "UNOPENED"
