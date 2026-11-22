"""Quota and representation semantics; invented metadata is not raw evidence."""

import json
from pathlib import Path

from test_supplemental_plan import registration
from test_supplemental_sources import prospective as prospective
from test_training_sources import commit

from ml.supplemental_design import load_design, make_plan
from ml.training_sources import digest

ROOT = Path(__file__).resolve().parents[1]


def test_attempt_selector_counts_one_finalized_attempt_per_intended_unit(tmp_path):
    from ml.supplemental_dataset import select_attempts

    d = load_design(ROOT / "config/supplemental-design.yaml")
    plan = make_plan(d, registration(d), seed=42)
    for unit in plan["runs"]:
        attempts = unit["attempts"][:2] if unit == plan["runs"][0] else unit["attempts"][:1]
        for i, attempt in enumerate(attempts):
            folder = tmp_path / "evidence/scenario-runs" / attempt["run_id"]
            folder.mkdir(parents=True)
            status = "ABORTED" if len(attempts) == 2 and i == 0 else "FINALIZED"
            (folder / ".collection_state.json").write_text(json.dumps({"status": status}))
    selected, issues = select_attempts(plan, tmp_path)
    assert issues == []
    assert len(selected) == 216
    assert selected[0]["attempt_number"] == 2
    unit = plan["runs"][0]
    path = tmp_path / "evidence/scenario-runs" / unit["run_id"] / ".collection_state.json"
    path.write_text(json.dumps({"status": "FINALIZED"}))
    selected, issues = select_attempts(plan, tmp_path)
    assert any(i["code"] == "DUPLICATE_PLANNED_UNIT" for i in issues)
    assert len(selected) == 215


def test_incomplete_attempt_selection_never_claims_collection_complete(tmp_path):
    from ml.supplemental_dataset import select_attempts

    d = load_design(ROOT / "config/supplemental-design.yaml")
    plan = make_plan(d, registration(d), seed=42)
    selected, issues = select_attempts(plan, tmp_path)
    assert not selected
    assert len([i for i in issues if i["code"] == "MISSING_PLANNED_UNIT"]) == 216


def test_orphan_raw_retry_cannot_be_treated_as_not_started(tmp_path):
    from ml.supplemental_dataset import select_attempts

    d = load_design(ROOT / "config/supplemental-design.yaml")
    plan = make_plan(d, registration(d), seed=42)
    for unit in plan["runs"]:
        folder = tmp_path / "evidence/scenario-runs" / unit["run_id"]
        folder.mkdir(parents=True)
        (folder / ".collection_state.json").write_text('{"status":"FINALIZED"}')
    orphan = plan["runs"][0]["attempts"][1]["run_id"]
    (tmp_path / "data/raw" / orphan).mkdir(parents=True)
    selected, issues = select_attempts(plan, tmp_path)
    assert any(i["code"] == "ORPHAN_RAW_ATTEMPT" and i["run_id"] == orphan for i in issues)
    assert len(selected) == 215


def test_new_projection_audit_uses_actual_model_inputs_and_preserves_old24_guard():
    from ml.supplemental_dataset import representation_audit

    schema = json.loads((ROOT / "ml/feature_schema_http.json").read_bytes())
    f = dict.fromkeys(schema["required"], 0.0)
    rows = [
        dict(run_id="a", family="c2", label=0, features={**f, "http_method_switch_fraction": 0.3}),
        dict(run_id="b", family="c2", label=1, features={**f, "http_method_switch_fraction": 1.0}),
    ]
    proof = representation_audit(rows, schema)
    assert proof["selected_input_collisions"] == []
    assert proof["legacy24_collision_count"] == 1
    rows[1]["features"]["http_method_switch_fraction"] = 0.3
    assert representation_audit(rows, schema)["selected_input_collisions"]
    # This new audit does not mutate the frozen legacy schema/feature space.
    old = json.loads((ROOT / "ml/feature_schema.json").read_bytes())
    assert len(old["required"]) == 24 and old["version"] == "features-v3"


def build_fixture(prospective, tmp_path, monkeypatch, *, mutate_after_audit=False):
    from ml import supplemental_dataset as d

    root, old, parts, review, _ = prospective
    inputs = tmp_path / "input-project"
    (inputs / "data/raw").mkdir(parents=True)
    (inputs / "evidence/scenario-runs").mkdir(parents=True)
    plan_path = inputs / "plan.json"
    plan_path.write_text(json.dumps(old["plan"]))
    inventory = d.input_inventory(inputs, plan_path)
    report = dict(
        status="SUPPLEMENTAL_COLLECTION_AUDIT_PASS",
        counts=old["record_counts"],
        input_inventory_sha256=digest(inventory),
        issues=[],
    )

    def audited(*a, **kw):
        if mutate_after_audit:
            (inputs / "data/raw/changed.txt").write_text("changed after audit")
        return (
            report,
            parts,
            old["collection_audit"]["source_compatibility"]["candidate"],
            {"synthetic": "test infrastructure, not G7"},
            old["design"],
            old["plan"],
        )

    monkeypatch.setattr(d, "audit_collection", audited)
    monkeypatch.setattr(d, "runtime_identity", lambda: review["processing_runtimes"][0])
    monkeypatch.setattr(d.lineage, "ROOT", root)
    return d, root, inputs, plan_path, review


def test_builder_atomically_publishes_and_stage_exports_only_four_safe_files(
    prospective,
    tmp_path,
    monkeypatch,
):
    d, root, inputs, plan_path, review = build_fixture(prospective, tmp_path, monkeypatch)
    processed = root / "data/processed-unit"
    receipt = d.build_dataset(inputs, plan_path, processed, processor_root=root)
    assert receipt["status"] == "BUILT_REQUIRES_EXACT_REVIEW"
    assert {p.name for p in processed.iterdir()} == {
        "train.jsonl",
        "validation.jsonl",
        "locked_test.jsonl",
        "dataset_manifest.json",
        "build_receipt.json",
    }
    output = tmp_path / "colab"
    import pytest

    with pytest.raises(ValueError, match="exact committed"):
        d.stage_dataset(processed, output)
    assert not output.exists()
    manifest = json.loads((processed / "dataset_manifest.json").read_bytes())
    review["approved_manifest_sha256"] = digest(manifest)
    (root / d.lineage.POLICY_RELATIVE).write_text(json.dumps(review))
    commit(root)
    before = Path.read_bytes

    def no_locked_read(path):
        if path.name == "locked_test.jsonl":
            raise AssertionError("staging must not read locked data")
        return before(path)

    monkeypatch.setattr(Path, "read_bytes", no_locked_read)
    d.stage_dataset(processed, output)
    assert {p.name for p in output.iterdir()} == {
        "train.jsonl",
        "validation.jsonl",
        "dataset_manifest.json",
        "colab-upload.sha256",
    }


def test_changed_inputs_fail_before_publishing_dataset(prospective, tmp_path, monkeypatch):
    import pytest

    d, root, inputs, plan_path, _ = build_fixture(
        prospective,
        tmp_path,
        monkeypatch,
        mutate_after_audit=True,
    )
    output = root / "data/processed-unit"
    with pytest.raises(ValueError, match="changed after audit"):
        d.build_dataset(inputs, plan_path, output, processor_root=root)
    assert not output.exists()


def test_native_collection_failure_becomes_structured_cli_error(tmp_path, monkeypatch, capsys):
    from ml import supplemental_dataset as d
    from ml.scenario_collection import CollectionError

    def corrupt_retry(*a, **kw):
        raise CollectionError("invalid retry predecessor snapshot")

    monkeypatch.setattr(d, "audit_collection", corrupt_retry)
    output = tmp_path / "report.json"
    assert (
        d.main(
            [
                "audit",
                "--input-project",
                str(tmp_path),
                "--plan",
                "unused.json",
                "--output",
                str(output),
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "ERROR" and "retry predecessor" in report["detail"]
    assert not output.exists()
