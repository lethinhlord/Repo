"""Offline inference preserves calibrated probabilities and authenticates before pickle."""

import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docs/development-runtime/predict.py"


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location("docker_predict", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def archive(tmp_path):
    x = np.array([[0, 0], [1, 0], [0, 1], [3, 4], [4, 3], [5, 5]])
    estimator = CalibratedClassifierCV(LogisticRegression(), cv=2).fit(x, [0, 0, 0, 1, 1, 1])
    metadata = {
        "artifact_kind": "development-model-v1", "model_version": "test-development",
        "deployment_eligible": False, "automation_eligible": False,
        "external_validation_status": "NOT_COLLECTED", "locked_test_status": "NOT_COLLECTED",
        "git_commit": "a" * 40, "dataset_hash_sha256": "b" * 64,
        "feature_schema_version": "test-schema",
    }
    families = {name: dict(estimator=estimator, feature_order=order,
                           model_name="logistic_regression", development_threshold=0.4)
                for name, order in (("account", ["a", "b"]), ("c2", ["b", "a"]))}
    buffer = io.BytesIO()
    joblib.dump(dict(artifact_kind="development-model-v1", metadata=metadata,
                     families=families), buffer)
    schema = {"version": "test-schema", "properties": {
        "a": {"type": "number", "minimum": 0},
        "b": {"type": "number", "minimum": 0}},
        "x-family-features": {k: v["feature_order"] for k, v in families.items()}}
    metrics = {"families": {k: {"selected_model": "logistic_regression",
                                "threshold_selection": {"threshold": 0.4}} for k in families}}
    members = {
        "development-model/development_model.joblib": buffer.getvalue(),
        "development-model/metadata.json": json.dumps(metadata).encode(),
        "development-model/feature_schema.json": json.dumps(schema).encode(),
        "development-model/metrics_development.json": json.dumps(metrics).encode(),
        "development-model/eda_train.json": b"{}",
        "evidence/development-experiment-summary.json": b"{}",
        "evidence/development-training.log": b"unit-test fixture, not real training evidence",
    }
    return tmp_path, members, estimator


def pack(root, members, extra=None):
    path = root / "model.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, content in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            tar.addfile(member, io.BytesIO(content))
        if extra:
            tar.addfile(extra)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_wrong_checksum_never_deserializes(runner, archive, monkeypatch):
    root, members, _ = archive
    path, _ = pack(root, members)
    loaded = []
    monkeypatch.setattr(joblib, "load", lambda *args: loaded.append(True))
    with pytest.raises(ValueError, match="SHA-256"):
        runner.load_archive(path, "0" * 64)
    assert not loaded


@pytest.mark.parametrize("kind", ["traversal", "symlink", "duplicate", "missing"])
def test_rejects_unsafe_or_incomplete_archive(runner, archive, kind):
    root, members, _ = archive
    extra = None
    if kind == "traversal":
        members["../escape"] = b"bad"
    elif kind == "symlink":
        extra = tarfile.TarInfo("link")
        extra.type, extra.linkname = tarfile.SYMTYPE, "/etc/passwd"
    elif kind == "duplicate":
        extra = tarfile.TarInfo("development-model/metadata.json")
    else:
        del members["development-model/metadata.json"]
    path, checksum = pack(root, members, extra)
    with pytest.raises(ValueError, match="archive"):
        runner.load_archive(path, checksum)


def test_inference_retains_calibration_order_threshold_and_scope(runner, archive):
    root, members, estimator = archive
    path, checksum = pack(root, members)
    payload, schema = runner.load_archive(path, checksum)
    rows = [{"family": "c2", "features": {"a": 1, "b": 3}, "label": 0, "run_id": "R1"},
            {"family": "account", "features": {"a": 1, "b": 3}, "run_id": "R2"}]
    result = runner.predict_records(payload, schema, rows)
    expected = estimator.predict_proba(np.array([[3, 1], [1, 3]]))[:, 1]
    assert [p["probability_malicious"] for p in result] == pytest.approx(expected)
    assert [p["development_prediction"] for p in result] == [int(p >= 0.4) for p in expected]
    assert all(p["automation_eligible"] is p["deployment_eligible"] is False for p in result)
    assert [p["run_id"] for p in result] == ["R1", "R2"]


def test_accepts_standard_tar_directory_headers(runner, archive):
    root, members, _ = archive
    directory = tarfile.TarInfo("development-model")
    directory.type = tarfile.DIRTYPE
    path, checksum = pack(root, members, directory)
    payload, _ = runner.load_archive(path, checksum)
    assert set(payload["families"]) == {"account", "c2"}


@pytest.mark.parametrize("bad", [True, float("nan"), float("inf"), "1", -1])
def test_rejects_invalid_numeric_features(runner, archive, bad):
    root, members, _ = archive
    path, checksum = pack(root, members)
    payload, schema = runner.load_archive(path, checksum)
    with pytest.raises(ValueError, match="feature"):
        runner.predict_records(payload, schema, [{"family": "account",
                                                 "features": {"a": bad, "b": 1}}])


@pytest.mark.parametrize("row", [
    {"family": "other", "features": {"a": 1, "b": 1}},
    {"family": "account", "features": {"a": 1}},
    {"family": "account", "features": {"a": 1, "b": 1, "typo": 2}},
])
def test_rejects_unknown_family_and_wrong_features(runner, archive, row):
    root, members, _ = archive
    path, checksum = pack(root, members)
    payload, schema = runner.load_archive(path, checksum)
    with pytest.raises(ValueError):
        runner.predict_records(payload, schema, [row])


def test_deployment_flag_cannot_be_accepted(runner, archive):
    root, members, _ = archive
    name = "development-model/metadata.json"
    metadata = json.loads(members[name])
    metadata["automation_eligible"] = True
    members[name] = json.dumps(metadata).encode()
    path, checksum = pack(root, members)
    with pytest.raises(ValueError, match="development"):
        runner.load_archive(path, checksum)
