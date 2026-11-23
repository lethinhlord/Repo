"""Execute orchestration guards/export; fixtures are not trained lab models."""

import ast
import json
import sys
import tarfile
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def notebook():
    return json.loads((ROOT / "notebooks/supplemental_train_colab.ipynb").read_bytes())


def cell(number):
    return "".join(notebook()["cells"][number]["source"])


def test_supplemental_notebook_parses_all_cells_and_nested_preflight():
    for c in notebook()["cells"]:
        if c["cell_type"] == "code":
            ast.parse("".join(c["source"]))
    tree = ast.parse(cell(12))
    preflight = tree.body[0].value.value
    ast.parse(preflight)
    assert 'eda["independent_host_days"]' in preflight


def test_notebook_refuses_unpinned_source_before_git_or_install(tmp_path, monkeypatch):
    google = types.ModuleType("google")
    colab = types.ModuleType("google.colab")
    colab.drive = types.SimpleNamespace(mount=lambda *a: None)
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.colab", colab)
    env = {}
    exec(cell(2), env)
    env.update(PROJECT_DIR=tmp_path / "missing", DRIVE_DATA_DIR=tmp_path / "missing-drive")
    with pytest.raises(RuntimeError, match="owner-approved"):
        exec(cell(4), env)
    assert not env["PROJECT_DIR"].exists()


def test_notebook_exports_unique_package_without_raw_and_refuses_overwrite(tmp_path):
    project = tmp_path / "checkout"
    package = project / "ml/model-package-supplemental-v1"
    package.mkdir(parents=True)
    (package / "metadata.json").write_text('{"fixture":"not a trained model"}')
    evidence = project / "operator-logs/supplemental-colab"
    evidence.mkdir(parents=True)
    (evidence / "supplemental-colab-training.log").write_text("synthetic orchestration test")
    version = "week3-20261122T000000Z"
    env = dict(
        json=json,
        PROJECT_DIR=project,
        PACKAGE_DIR=package,
        EVIDENCE_DIR=evidence,
        DRIVE_OUTPUT_DIR=tmp_path / "fake-drive",
        RANDOM_SEED=42,
        commit="a" * 40,
        manifest={"group_key": "evaluation_group_id"},
        metadata=dict(
            model_version=version, dataset_hash_sha256="b" * 64, dataset_provenance={},
            dataset_manifest_payload_sha256="c" * 64,
            evaluation_protocol="known-template-new-host-day",
            supplemental_scope={"automation_eligible": False}, locked_test_status="UNOPENED",
        ),
        metrics={"families": {"c2": {"selected_model": "fixture"}}},
        thresholds={"families": {"c2": {"automation_eligible": False}}},
        package_audit={"passed": True},
    )
    exec(cell(23), env)
    path = env["destination"]
    assert version in path.name
    raw = path.read_bytes()
    with tarfile.open(path) as tar:
        names = tar.getnames()
        assert "ml/model-package/metadata.json" in names
        assert not any("locked_test" in n or "data/raw" in n for n in names)
    with pytest.raises(FileExistsError):
        exec(cell(23), env)
    assert path.read_bytes() == raw
