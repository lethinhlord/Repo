"""Real parser/serialization paths; synthetic metadata never grants lab acceptance."""

import json
from datetime import date
from pathlib import Path

import yaml
from test_supplemental_plan import registration

from ml.supplemental_design import load_design, make_plan
from scripts.supplemental_collection import campaign_progress, main, registration_template

ROOT = Path(__file__).resolve().parents[1]


def test_registration_cli_is_incomplete_until_operator_supplies_real_context(tmp_path, capsys):
    design = load_design(ROOT / "config/supplemental-design.yaml")
    template = registration_template(design, date(2027, 1, 1), "Kien")
    reg = tmp_path / "registration.json"
    reg.write_text(json.dumps(template))
    output = tmp_path / "plan.json"
    args = [
        "--project-root",
        str(ROOT),
        "plan",
        "--registration",
        str(reg),
        "--output",
        str(output),
    ]
    assert main(args) == 1
    assert not output.exists()
    reg.write_text(json.dumps(registration(design)))
    assert main(args) == 0
    assert json.loads(output.read_bytes()) == make_plan(design, registration(design), seed=42)
    assert main(["--project-root", str(ROOT), "verify-plan", "--plan", str(output)]) == 0
    assert "PLAN_VERIFIED" in capsys.readouterr().out
    before = output.read_bytes()
    assert main(args) == 1  # Refuse replacing a frozen plan.
    assert output.read_bytes() == before


def test_progress_selects_predeclared_retry_and_never_claims_audited_quality(tmp_path):
    design = load_design(ROOT / "config/supplemental-design.yaml")
    plan = make_plan(design, registration(design), seed=42)
    row = plan["runs"][0]
    folder = tmp_path / "evidence/scenario-runs" / row["run_id"]
    folder.mkdir(parents=True)
    (folder / ".collection_state.json").write_text(json.dumps({"status": "ABORTED"}))
    value = campaign_progress(plan, tmp_path, row["context"]["collection_date"])
    assert value["status"] == "SCHEDULE_ONLY_REQUIRES_FULL_AUDIT"
    retry = next(r for r in value["due"] if r["planned_run_id"] == row["run_id"])
    assert retry["attempt_number"] == 2
    assert retry["run_id"] == row["attempts"][1]["run_id"]


def test_compiled_tracked_catalog_and_source_pass_actual_design_gate():
    from ml.collection_release import _check_design
    from ml.supplemental_catalog import compile_catalog

    design = load_design(ROOT / "config/supplemental-design.yaml")
    actual = yaml.safe_load((ROOT / "config/supplemental-catalog.yaml").read_bytes())
    old = yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_bytes())
    assert actual == compile_catalog(design, old)
    _check_design(ROOT, ROOT / "config/supplemental-sources.yaml")


def test_real_git_keeps_generated_campaign_artifacts_out_of_source_identity(tmp_path):
    from test_training_sources import commit, git

    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "core.autocrlf", "false")
    (tmp_path / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
    (tmp_path / "source.py").write_text("source = True\n")
    commit(tmp_path)
    for name in (
        "evidence/supplemental-acceptance.json",
        "data/processed-supplemental-v1/train.jsonl",
        "ml/model-package-supplemental-v1/metadata.json",
        "data/.tmp-supplemental-build-UNIT/complete/train.jsonl",
        "evidence/development-acceptance.json",
        "data/processed-development-v1/train.jsonl",
        "ml/development-model-v1/metadata.json",
        "ml/.tmp-development-model-UNIT/complete/metadata.json",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic generated artifact\n")
    assert git(tmp_path, "status", "--porcelain", "--untracked-files=all") == ""
    (tmp_path / "new_source.py").write_text("new = True\n")
    assert "new_source.py" in git(tmp_path, "status", "--porcelain", "--untracked-files=all")


def test_native_collection_error_is_reported_without_partial_parameter_export(
    tmp_path, monkeypatch, capsys,
):
    from ml.scenario_collection import CollectionError

    def corrupt_snapshot(*args):
        raise CollectionError("frozen start contract differs")

    monkeypatch.setattr("scripts.export_run_parameters.load_frozen_parameters", corrupt_snapshot)
    output = tmp_path / "parameters.json"
    assert main([
        "--project-root", str(ROOT), "parameters", "--run-id", "test-run",
        "--output", str(output),
    ]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ERROR" and "start contract" in result["detail"]
    assert not output.exists()
