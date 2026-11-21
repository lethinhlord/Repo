"""Execute notebook gates with synthetic staging; never launch Colab or train."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks/week3_train_colab.ipynb"


def _cell(marker: str, stream: bool = False) -> str:
    path = NOTEBOOK.with_name("week3_train_stream_colab.ipynb") if stream else NOTEBOOK
    notebook = json.loads(path.read_text(encoding="utf-8"))
    return next("".join(cell["source"]) for cell in notebook["cells"]
                if marker in "".join(cell["source"]))


@pytest.mark.parametrize("reject", [False, True])
@pytest.mark.parametrize("stream", [False, True])
def test_preinstall_verifies_reviewed_metadata_before_reading_partitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reject: bool, stream: bool,
) -> None:
    sha = "a" * 40
    staging = tmp_path / "staging"
    staging.mkdir()
    project = tmp_path / "checkout"
    config = b"SYNTHETIC-NOT-LAB-config\n"
    design = b"SYNTHETIC-NOT-LAB-design\n"
    design_hash = hashlib.sha256(design).hexdigest()
    manifest = {
        "manifest_version": "dataset-manifest-v3",
        "group_key": "cohort_id", "locked_test_status": "UNOPENED",
        "collection_audit": {"collection_design_sha256": design_hash},
        "provenance": {
            "builder_git_commit": sha,
            "builder_config_sha256": hashlib.sha256(config).hexdigest(),
            "collection_design_sha256": design_hash,
        },
    }
    if stream:
        manifest["manifest_version"] = "dataset-manifest-v4-stream-v1"
        manifest["parent_manifest"] = {
            "provenance": {"collection_design_sha256": design_hash},
            "collection_audit": {"collection_design_sha256": design_hash},
        }
    names = ("train.jsonl", "validation.jsonl", "dataset_manifest.json")
    for name in names[:2]:
        (staging / name).write_bytes(b"SYNTHETIC-NOT-LAB\n")
    (staging / names[2]).write_text(json.dumps(manifest), encoding="utf-8")
    (staging / "colab-upload.sha256").write_text("".join(
        f"{hashlib.sha256((staging / name).read_bytes()).hexdigest()}  {name}\n"
        for name in names
    ), encoding="utf-8")
    events = []

    def verify(value, rows_by_partition=None, *, root=None, expected_commit=None):
        assert value == manifest
        assert rows_by_partition is None
        assert root == project and expected_commit == sha
        events.append("source verification")
        if reject:
            raise ValueError("reviewed source certificate rejected")

    module_name = "ml.stream_sources" if stream else "ml.training_sources"
    source_module = types.ModuleType(module_name)
    verifier_name = "verify_stream_manifest" if stream else "verify_training_manifest"
    setattr(source_module, verifier_name, verify)
    google = types.ModuleType("google")
    colab = types.ModuleType("google.colab")
    colab.drive = types.SimpleNamespace(mount=lambda _: None)
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.colab", colab)
    monkeypatch.setitem(sys.modules, module_name, source_module)

    def run(command, **kwargs):
        if command[1] == "clone":
            (project / "ml").mkdir(parents=True)
            (project / "config").mkdir()
            config_name = "training_stream_config.yaml" if stream else "training_config.yaml"
            (project / "ml" / config_name).write_bytes(config)
            (project / "config/collection-design.yaml").write_bytes(design)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: sha)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.chdir(tmp_path)
    original_read_bytes = Path.read_bytes

    def read_bytes(path):
        if path.parent == staging and path.name in names[:2]:
            assert events == ["source verification"], "partition opened before source verification"
            assert not reject, "rejected source must not open a partition"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    namespace = {
        "DRIVE_DATA_DIR": staging, "PROJECT_DIR": project,
        "EXPECTED_TRAINING_COMMIT": sha, "BRANCH": "main", "REPO_URL": "synthetic://source",
        "EXPECTED_FILES": (*names, "colab-upload.sha256"), "EXPECTED_DATA_FILES": names,
        "CHECKSUM_FILE": "colab-upload.sha256",
    }
    gate = _cell("# Read only the staged manifest", stream)
    if reject:
        with pytest.raises(ValueError, match="reviewed source certificate rejected"):
            exec(gate, namespace)
    else:
        exec(gate, namespace)
    assert events == ["source verification"]


class _Table:
    def __init__(self, _rows):
        pass

    def sort_values(self, *args, **kwargs):
        return self


@pytest.mark.parametrize("mismatch", [False, True])
@pytest.mark.parametrize("stream", [False, True])
def test_result_and_archive_bind_and_export_the_reviewed_provenance(
    tmp_path: Path, mismatch: bool, stream: bool,
) -> None:
    package = tmp_path / ("ml/model-package-stream-v1" if stream else "ml/model-package")
    package.mkdir(parents=True)
    certificate = {"review_id": "SYNTHETIC-NOT-LAB"}
    certificate_hash = hashlib.sha256(
        json.dumps(certificate, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()
    manifest = {
        "manifest_version": "dataset-manifest-v3", "group_key": "cohort_id",
        "dataset_hash_sha256": "d" * 64,
        "collection_audit": {"source_compatibility": certificate},
        "provenance": {"source_compatibility_sha256": certificate_hash},
    }
    metadata = {
        "model_version": "week3-SYNTHETIC-NOT-LAB", "locked_test_status": "UNOPENED",
        "dataset_hash_sha256": manifest["dataset_hash_sha256"],
        "dataset_provenance": {"source_compatibility_sha256": "0" * 64}
        if mismatch else manifest["provenance"],
        "dataset_source_compatibility": certificate,
        "dataset_manifest_payload_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest(),
    }
    if stream:
        manifest["manifest_version"] = "dataset-manifest-v4-stream-v1"
        manifest["parent_manifest_sha256"] = "a" * 64
        metadata["parent_manifest_sha256"] = manifest["parent_manifest_sha256"]
        metadata["dataset_manifest_payload_sha256"] = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()
    documents = {
        "metadata.json": metadata, "metrics_validation.json": {"families": {}},
        "thresholds.json": {"families": {}}, "leakage_audit.json": {"passed": True},
        "eda_train.json": {}, "calibration_validation.json": {}, "feature_profile.json": {},
        "feature_schema.json": {},
    }
    for name, document in documents.items():
        (package / name).write_text(json.dumps(document), encoding="utf-8")
    (package / "model.joblib").write_bytes(b"SYNTHETIC-NOT-A-MODEL")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    stem = "week3-stream-colab" if stream else "week3-colab"
    (evidence / f"{stem}-training.log").write_text("SYNTHETIC-NOT-LAB\n", encoding="utf-8")
    namespace = {
        "PROJECT_DIR": tmp_path, "DRIVE_OUTPUT_DIR": tmp_path / "results",
        "EVIDENCE_DIR": evidence, "Path": Path, "json": json, "hashlib": hashlib,
        "manifest": manifest, "pd": types.SimpleNamespace(DataFrame=_Table),
        "display": lambda _: None, "commit": "a" * 40, "RANDOM_SEED": 42,
    }
    result = _cell("candidate_rows = []", stream)
    if mismatch:
        with pytest.raises(AssertionError):
            exec(result, namespace)
        return
    exec(result, namespace)
    exec(_cell("experiment_summary = {", stream), namespace)
    with tarfile.open(namespace["destination"]) as archive:
        summary = json.load(archive.extractfile(f"evidence/{stem}-experiment-summary.json"))
        archived_metadata = json.load(archive.extractfile("ml/model-package/metadata.json"))
        assert not any("locked_test" in name or "data/raw" in name for name in archive.getnames())
    assert summary["dataset_provenance"] == manifest["provenance"]
    assert summary["dataset_source_compatibility"] == certificate
    assert archived_metadata["dataset_source_compatibility"] == certificate
