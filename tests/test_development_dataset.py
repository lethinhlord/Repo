"""Atomic publication/staging, with mocked native audit tested separately by G7."""

import json
from copy import deepcopy
from datetime import date

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


@pytest.mark.parametrize("case", ["future", "overdue", "corrupt", "ambiguity"])
def test_progress_review_distinguishes_uncollected_units_from_bad_evidence(
    development_data, monkeypatch, case
):
    _, _, _, _, _, original = development_data
    audited = deepcopy(original)
    report, parts, _, _, _, plan = audited
    missing = [r for r in plan["runs"] if r["context"]["collection_date"] != "2026-12-01"]
    missing_ids = {r["run_id"] for r in missing}
    parts["train"] = [r for r in parts["train"] if r["planned_run_id"] not in missing_ids]
    report.update(
        status="SUPPLEMENTAL_COLLECTION_AUDIT_FAIL",
        counts={"train": 16},
        issues=[dict(code="MISSING_PLANNED_UNIT", run_id=r["run_id"]) for r in missing],
    )
    if case != "future" and case != "overdue":
        report["issues"].append(
            dict(
                code=(
                    "RAW_EVIDENCE_OR_FEATURES_INVALID"
                    if case == "corrupt"
                    else "TRAIN_SELECTED_REPRESENTATION_AMBIGUITY"
                ),
                run_id="CAMPAIGN",
            )
        )
    monkeypatch.setattr(d, "audit_collection", lambda *a, **kw: audited)
    result = d.review_progress(None, None, today=date(2026, 12, 3 if case == "overdue" else 1))
    assert result["status"] == (
        "DEVELOPMENT_PROGRESS_REPLAY_IN_PROGRESS"
        if case == "future"
        else "DEVELOPMENT_PROGRESS_REPLAY_BLOCKED"
    )
    assert result["full_audit"]["issues"] == report["issues"]
    assert len(result["uncollected_units"]) == 32
    assert result["dataset_ready"] is False
    assert result["automation_eligible"] is False
    assert sum(r["verified_runs"] for r in result["template_coverage"]) == 16


def test_complete_progress_is_still_not_dataset_approval(development_data, monkeypatch):
    audited = development_data[-1]
    monkeypatch.setattr(d, "audit_collection", lambda *a, **kw: audited)
    result = d.review_progress(None, None, today=date(2026, 12, 3))
    assert result["status"] == "DEVELOPMENT_PROGRESS_REPLAY_COMPLETE"
    assert result["dataset_ready"] is False and result["uncollected_units"] == []


@pytest.mark.parametrize("blocked", [False, True])
def test_progress_cli_exit_preserves_blocking_status(tmp_path, monkeypatch, blocked):
    status = "DEVELOPMENT_PROGRESS_REPLAY_" + ("BLOCKED" if blocked else "IN_PROGRESS")
    monkeypatch.setattr(d, "review_progress", lambda *args: {"status": status})
    output = tmp_path / "report.json"
    code = d.main(
        [
            "review-progress",
            "--input-project",
            str(tmp_path),
            "--plan",
            str(tmp_path / "plan.json"),
            "--output",
            str(output),
        ]
    )
    assert code == int(blocked)
    assert json.loads(output.read_bytes())["status"] == status
