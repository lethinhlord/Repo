"""Atomic publication/staging, with mocked native audit tested separately by G7."""

import json

import pytest
from test_development_sources import development_data as development_data
from test_training_sources import commit

from ml import development_dataset as d
from ml import development_sources as s


def setup_builder(development_data, tmp_path, monkeypatch, mutate=False):
    root, _, _, review, _, audited = development_data
    inputs = tmp_path / "native-input"
    (inputs / "data/raw").mkdir(parents=True)
    (inputs / "evidence/scenario-runs").mkdir(parents=True)
    plan = inputs / "plan.json"
    plan.write_text(json.dumps(audited[-1]))
    audited[0]["input_inventory_sha256"] = s.digest(d.shared.input_inventory(inputs, plan))

    def native(*a, **kw):
        if mutate:
            (inputs / "data/raw/unexpected.json").write_text("changed after audit")
        return audited

    monkeypatch.setattr(d, "audit_collection", native)
    monkeypatch.setattr(d, "runtime_identity", lambda: review["processing_runtimes"][0])
    monkeypatch.setattr(s, "ROOT", root)
    return root, inputs, plan, review


def test_build_requires_exact_review_then_stages_three_files(
    development_data, tmp_path, monkeypatch
):
    root, inputs, plan, review = setup_builder(development_data, tmp_path, monkeypatch)
    processed = root / "data/processed-development-v1"
    receipt = d.build_dataset(inputs, plan, processed, processor_root=root)
    assert receipt["status"] == "DEVELOPMENT_BUILT_REQUIRES_EXACT_REVIEW"
    assert {p.name for p in processed.iterdir()} == {
        "train.jsonl",
        "dataset_manifest.json",
        "build_receipt.json",
    }
    output = tmp_path / "colab-only"
    with pytest.raises(ValueError, match="exact committed"):
        d.stage_dataset(processed, output)
    assert not output.exists()
    manifest = json.loads((processed / "dataset_manifest.json").read_bytes())
    review["approved_manifest_sha256"] = s.digest(manifest)
    (root / s.POLICY_RELATIVE).write_text(json.dumps(review))
    commit(root)
    d.stage_dataset(processed, output)
    assert {p.name for p in output.iterdir()} == {
        "train.jsonl",
        "dataset_manifest.json",
        "colab-upload.sha256",
    }
    with pytest.raises(ValueError, match="fresh path"):
        d.stage_dataset(processed, output)


def test_mutating_raw_cannot_publish_any_dataset(development_data, tmp_path, monkeypatch):
    root, inputs, plan, _ = setup_builder(development_data, tmp_path, monkeypatch, mutate=True)
    output = root / "data/processed-development-v1"
    with pytest.raises(ValueError, match="changed"):
        d.build_dataset(inputs, plan, output, processor_root=root)
    assert not output.exists()
