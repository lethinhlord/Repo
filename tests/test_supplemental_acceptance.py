"""Synthetic four-transport/G7/restore contract; not Kiên's real lab acceptance."""

import hashlib
import json
from datetime import date, timedelta
from pathlib import Path
from shutil import copyfile

import pytest
import test_collection_acceptance as fixture
import yaml
from test_official_collection_acceptance import prepare_official
from test_preflight_report_binding import NONCE, START, canary_rows
from test_supplemental_plan import registration

from ml import collection_release as release
from ml.preflight import verify_preflight_capture
from ml.scenario_collection import (
    CollectionError,
    RunDraft,
    ScenarioCatalog,
    SourceConfig,
    abort_run,
    create_run_draft,
    start_run,
)
from ml.supplemental_catalog import PILOTS, compile_catalog
from ml.supplemental_design import load_design, make_plan, resolve_plan_run, write_plan

ROOT = Path(__file__).resolve().parents[1]


def test_v3_acceptance_freezes_plan_and_restores_all_four_transport_pilots(tmp_path, monkeypatch):
    archive, source_path, _, candidate = prepare_official(tmp_path, monkeypatch)
    copyfile(ROOT / "config/supplemental-design.yaml", tmp_path / "config/supplemental-design.yaml")
    d = load_design(tmp_path / "config/supplemental-design.yaml")
    candidate["tag"] = d["candidate_tag"]
    catalog = compile_catalog(
        d, yaml.safe_load((tmp_path / "config/scenario-catalog.yaml").read_bytes())
    )
    catalog_path = tmp_path / "config/supplemental-catalog.yaml"
    catalog_path.write_text(yaml.safe_dump(catalog), encoding="utf-8")
    cfg = yaml.safe_load(source_path.read_bytes())
    cfg.update(
        scenario_catalog_path="config/supplemental-catalog.yaml",
        collection_release_path="evidence/supplemental-acceptance.json",
        campaign_plan_path="operator-logs/supplemental-plan.json",
        feature_scope="full-window",
    )
    source_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    registered = registration(d)
    for context in registered["contexts"]:
        delta = date.fromisoformat(context["collection_date"]) - date(2027, 1, 1)
        context["collection_date"] = (fixture.COLLECTION_BASE.date() + delta).isoformat()
    plan = make_plan(d, registered, seed=42)
    plan_path = tmp_path / cfg["campaign_plan_path"]
    write_plan(plan_path, plan)
    parsed = ScenarioCatalog.model_validate(catalog)
    pilots = [
        fixture._collect_run(
            tmp_path,
            archive,
            source_path,
            next(s for s in parsed.scenarios if s.scenario_id == name),
            sequence=i,
            repeat=0,
            purpose="pilot",
            catalog_path=catalog_path,
        )
        for i, name in enumerate(PILOTS)
    ]
    preflight = tmp_path / "operator-logs/preflight/SYNTHETIC"
    preflight.mkdir(parents=True)
    fresh = preflight / "archives-fresh.jsonl"
    fresh.write_text("".join(json.dumps(r) + "\n" for r in canary_rows()))
    report = verify_preflight_capture(
        fresh, NONCE.lower(), START.isoformat(), (START + timedelta(minutes=5)).isoformat()
    )
    (preflight / "channel-check.txt").write_text(json.dumps(report))
    (preflight / "capture.sha256").write_text(
        "".join(
            f"{hashlib.sha256((preflight / n).read_bytes()).hexdigest()}  {n}\n"
            for n in ("archives-fresh.jsonl", "channel-check.txt")
        )
    )
    backup = tmp_path.parent / (tmp_path.name + "-backup")
    release.create_backup(tmp_path, candidate["tag"], backup)
    accepted = release.create_acceptance(
        tmp_path,
        candidate["tag"],
        pilots,
        backup,
        preflight,
        tmp_path / cfg["collection_release_path"],
        source_config_path=source_path,
    )
    assert accepted["version"] == "collection-acceptance-v3"
    assert accepted["campaign_registration"]["plan"] == plan
    assert {
        json.loads(
            (tmp_path / "evidence/scenario-runs" / rid / ".collection_state.json").read_bytes()
        )["draft"]["scenario_parameters"]["transport"]
        for rid in pilots
    } == {
        "http",
        "dns",
        "smb",
        "console",
    }
    authorized = release.assert_collection_authorized(
        SourceConfig.model_validate(cfg), tmp_path, "trainable", source_path
    )
    assert authorized == accepted
    state = {
        **accepted["collection_contract"],
        "collection_candidate": candidate,
        "collection_release": accepted,
        "collection_release_sha256": release.digest(accepted),
        "draft": {"campaign_plan": plan},
    }
    release.verify_frozen_acceptance(state)
    state["draft"]["campaign_plan"] = None
    with pytest.raises(release.ReleaseError, match="campaign"):
        release.verify_frozen_acceptance(state)
    unit = plan["runs"][0]

    def draft_attempt(number):
        row = resolve_plan_run(plan, unit["attempts"][number - 1]["run_id"])
        at = fixture.COLLECTION_BASE + timedelta(minutes=50 + number)
        path = tmp_path / "run-drafts" / (row["run_id"] + ".yaml")
        create_run_draft(
            catalog_path,
            row["scenario_id"],
            row["run_id"],
            row["context"]["operator"],
            path,
            collection_seed=row["collection_seed"],
            campaign_plan=plan,
            source_config_path=source_path,
            clock_preflight=fixture._clock_preflight(at),
        )
        return row, path, at

    second, second_path, second_at = draft_attempt(2)
    with pytest.raises(CollectionError, match="retry predecessor"):
        start_run(second_path, source_path, tmp_path, now=second_at)
    first, first_path, first_at = draft_attempt(1)
    start_run(first_path, source_path, tmp_path, now=first_at)
    abort_run(first["run_id"], tmp_path, "SYNTHETIC failed native action; keep evidence")
    start_run(second_path, source_path, tmp_path, now=second_at)
    retry_state = json.loads(
        (
            tmp_path / "evidence/scenario-runs" / second["run_id"] / ".collection_state.json"
        ).read_bytes()
    )
    release.verify_frozen_acceptance(retry_state)
    assert RunDraft.model_validate(retry_state["draft"]).campaign_plan == plan
    abort_run(second["run_id"], tmp_path, "SYNTHETIC test finished; no training evidence")
    plan_path.write_text("{}")
    with pytest.raises(release.ReleaseError):
        release.assert_collection_authorized(
            SourceConfig.model_validate(cfg), tmp_path, "trainable", source_path
        )
