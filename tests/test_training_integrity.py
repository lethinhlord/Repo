from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest
import yaml

from ml.build_dataset import build_dataset
from ml.training import train, verify_training_partitions
from scripts.generate_smoke_dataset import generate

ROOT = Path(__file__).resolve().parents[1]


def prepare_dataset(root: Path) -> tuple[Path, dict]:
    generate(root / "raw")
    config = yaml.safe_load((ROOT / "config/training-smoke.yaml").read_text(encoding="utf-8"))
    config["feature_schema"] = str(ROOT / "ml/feature_schema.json")
    config["data"].update(
        raw_dir=str(root / "raw"), processed_dir=str(root / "processed"),
        splits_dir=str(root / "splits"),
    )
    config["package_dir"] = str(root / "ml/model-package")
    config_path = root / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path, build_dataset(config_path)


@pytest.mark.parametrize("partition", ["train", "validation"])
def test_training_rejects_a_partition_changed_after_build(
    tmp_path: Path, partition: str,
) -> None:
    config_path, _ = prepare_dataset(tmp_path)
    path = tmp_path / f"processed/{partition}.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[0]["features"]["failed_login_count"] += 0.123
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    with pytest.raises(ValueError, match="partition.*integrity"):
        train(config_path)


@pytest.mark.parametrize("changed_field", ["schema", "count", "manifest_type", "provenance"])
def test_partition_contract_rejects_inconsistent_metadata(
    tmp_path: Path, changed_field: str,
) -> None:
    prepare_dataset(tmp_path)
    path = tmp_path / "processed/dataset_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if changed_field == "schema":
        manifest["feature_schema_sha256"] = "0" * 64
    elif changed_field == "count":
        manifest["partitions"]["train"]["record_count"] += 1
    elif changed_field == "provenance":
        manifest.pop("provenance")
    else:
        manifest = []
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError):
        verify_training_partitions(
            tmp_path / "processed", ROOT / "ml/feature_schema.json", require_collection_audit=False,
        )


def test_real_lab_training_does_not_accept_an_unaudited_smoke_manifest(tmp_path: Path) -> None:
    prepare_dataset(tmp_path)

    with pytest.raises(ValueError, match="collection audit provenance"):
        verify_training_partitions(
            tmp_path / "processed", ROOT / "ml/feature_schema.json", require_collection_audit=True,
        )


def test_trainer_output_is_consumed_by_colab_result_and_archive_cells(
    tmp_path: Path,
) -> None:
    config_path, manifest = prepare_dataset(tmp_path)
    (tmp_path / "processed/locked_test.jsonl").unlink()
    metadata = train(config_path)
    notebook = json.loads((ROOT / "notebooks/week3_train_colab.ipynb").read_text(encoding="utf-8"))
    result_cell = next(
        "".join(cell["source"]) for cell in notebook["cells"]
        if "candidate_rows = []" in "".join(cell["source"])
    )
    archive_cell = next(
        "".join(cell["source"]) for cell in notebook["cells"]
        if "experiment_summary = {" in "".join(cell["source"])
    )

    class Table:
        def __init__(self, _rows):
            pass

        def sort_values(self, *args, **kwargs):
            return self

    class Tables:
        DataFrame = Table

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "week3-colab-training.log").write_text("synthetic test\n", encoding="utf-8")
    environment = {
        "PROJECT_DIR": tmp_path, "DRIVE_OUTPUT_DIR": tmp_path / "drive-results",
        "EVIDENCE_DIR": evidence_dir, "Path": Path, "json": json,
        "manifest": manifest, "pd": Tables, "display": lambda _: None,
        "commit": "synthetic-test", "RANDOM_SEED": 42,
    }
    exec(result_cell, environment)
    exec(archive_cell, environment)

    assert len(environment["candidate_rows"]) == 6
    destination = environment["destination"]
    assert destination.is_file()
    with tarfile.open(destination) as archive:
        names = archive.getnames()
    assert "ml/model-package/model.joblib" in names
    assert not any("locked_test" in name or "data/raw" in name for name in names)
    assert metadata["locked_test_status"] == "UNOPENED"
    assert metadata["training_partition_sha256"] == {
        name: manifest["partitions"][name]["sha256"] for name in ("train", "validation")
    }
    for family in environment["metrics"]["families"].values():
        result = family["candidates"][family["selected_model"]]["validation"]
        assert result["uncertainty"]["status"] == "INSUFFICIENT_INDEPENDENT_GROUPS"
        assert all(value["low"] is None for value in result["confidence_intervals"].values())
    for threshold in environment["thresholds"]["families"].values():
        assert threshold["automation_eligible"] is False
        assert "insufficient_validation_groups" in threshold["gate_failures"]
