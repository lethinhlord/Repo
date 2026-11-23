"""Development orchestration and export use fixtures, never real held-out data."""

import ast
import hashlib
import json
import shutil
import sys
import tarfile
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def cell(number):
    notebook = json.loads((ROOT / "notebooks/development_train_colab.ipynb").read_bytes())
    return "".join(notebook["cells"][number]["source"])


def test_development_notebook_code_and_nested_preflight_parse():
    notebook = json.loads((ROOT / "notebooks/development_train_colab.ipynb").read_bytes())
    for item in notebook["cells"]:
        if item["cell_type"] == "code":
            ast.parse("".join(item["source"]))
    preflight = ast.parse(cell(12)).body[0].value.value
    ast.parse(preflight)
    assert 'eda["independent_host_days"]' in preflight
    assert '"validation.jsonl"' not in cell(10)


def test_development_notebook_requires_owner_sha_before_git(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "google", types.ModuleType("google"))
    colab = types.ModuleType("google.colab")
    colab.drive = types.SimpleNamespace(mount=lambda *args: None)
    monkeypatch.setitem(sys.modules, "google.colab", colab)
    env = {}
    exec(cell(2), env)
    env.update(PROJECT_DIR=tmp_path / "checkout", DRIVE_DATA_DIR=tmp_path / "drive")
    with pytest.raises(RuntimeError, match="owner-approved"):
        exec(cell(4), env)
    assert not env["PROJECT_DIR"].exists()


def test_development_notebook_exports_offline_artifact_without_overwrite(tmp_path):
    project = tmp_path / "checkout"
    package = project / "ml/development-model-v1"
    package.mkdir(parents=True)
    (package / "metadata.json").write_text('{"fixture":"not a trained model"}')
    evidence = project / "operator-logs/development-colab"
    evidence.mkdir(parents=True)
    log = evidence / "development-training.log"
    log.write_text("synthetic orchestration fixture")
    version = "development-20261123T000000Z"
    env = dict(
        json=json, hashlib=hashlib, shutil=shutil, PROJECT_DIR=project,
        PACKAGE_DIR=package, EVIDENCE_DIR=evidence, SESSION_LOG=log,
        DRIVE_OUTPUT_DIR=tmp_path / "fake-drive", commit="a" * 40,
        metadata=dict(model_version=version, dataset_hash_sha256="b" * 64,
                      dataset_manifest_payload_sha256="c" * 64),
    )
    exec(cell(23), env)
    path = env["destination"]
    raw = path.read_bytes()
    with tarfile.open(path) as archive:
        names = archive.getnames()
        assert "development-model/metadata.json" in names
        assert not any("locked_test" in name or "data/raw" in name for name in names)
        summary = json.load(archive.extractfile("evidence/development-experiment-summary.json"))
    assert summary["automation_eligible"] is summary["deployment_eligible"] is False
    assert summary["locked_test_status"] == "NOT_COLLECTED"
    with pytest.raises(FileExistsError):
        exec(cell(23), env)
    assert path.read_bytes() == raw
