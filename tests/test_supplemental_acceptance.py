"""Synthetic four-transport/G7/restore contract; not Kiên's real lab acceptance."""

import hashlib
import json
from datetime import UTC, date, datetime, timedelta
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
    begin_action,
    complete_action,
    create_run_draft,
    finalize_run,
    start_run,
)
from ml.supplemental_catalog import PILOTS, compile_catalog
from ml.supplemental_design import load_design, make_plan, resolve_plan_run, write_plan

ROOT = Path(__file__).resolve().parents[1]


def test_v3_acceptance_freezes_plan_and_restores_all_four_transport_pilots(tmp_path, monkeypatch):
    archive, source_path, _, candidate = prepare_official(tmp_path, monkeypatch)
    copyfile(ROOT / "config/supplemental-design.yaml", tmp_path / "config/supplemental-design.yaml")
    copyfile(
        ROOT / "config/supplemental-sources.yaml", tmp_path / "config/supplemental-sources.yaml",
    )
    d = load_design(tmp_path / "config/supplemental-design.yaml")
    candidate["tag"] = d["candidate_tag"]
    # This isolated protocol fixture has synthetic source authority, just as its
    # capture_candidate above is synthetic. It never issues real VM acceptance.
    monkeypatch.setattr(
        "ml.supplemental_sources.require_collection_source",
        lambda root, tag: ({"status": "COLLECTION_READY"}, candidate["commit"]),
    )
    catalog = compile_catalog(
        d, yaml.safe_load((tmp_path / "config/scenario-catalog.yaml").read_bytes())
    )
    catalog_path = tmp_path / "config/supplemental-catalog.yaml"
    catalog_path.write_bytes((ROOT / "config/supplemental-catalog.yaml").read_bytes())
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

    def draft_attempt(number, unit_row=None, at=None):
        selected_unit = unit if unit_row is None else unit_row
        row = resolve_plan_run(plan, selected_unit["attempts"][number - 1]["run_id"])
        at = at or fixture.COLLECTION_BASE + timedelta(minutes=50 + number)
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
    from ml.supplemental_dataset import project_run

    def finish_and_project(planned, action_at):
        rid = planned["run_id"]
        started_state = json.loads(
            (tmp_path / "evidence/scenario-runs" / rid / ".collection_state.json").read_bytes()
        )
        run_draft = RunDraft.model_validate(started_state["draft"])
        scenario = next(s for s in parsed.scenarios if s.scenario_id == planned["scenario_id"])
        begin_action(rid, tmp_path, now=action_at)
        event_builder = (
            fixture._account_events if scenario.family == "account" else fixture._c2_events
        )
        events, last = event_builder(
            rid,
            scenario,
            run_draft,
            action_at
            + timedelta(seconds=run_draft.scenario_parameters["pre_action_delay_seconds"]),
        )
        with archive.open("a", encoding="utf-8") as stream:
            stream.write("".join(json.dumps(e) + "\n" for e in events))
        complete_action(rid, tmp_path, now=last + timedelta(seconds=2))
        window_end = datetime.fromtimestamp((int(action_at.timestamp()) // 300 + 1) * 300, UTC)
        finalize_run(rid, tmp_path, now=window_end + timedelta(seconds=60))
        return project_run(tmp_path, planned, plan, parsed, ROOT)

    projected = finish_and_project(
        second, fixture.COLLECTION_BASE + timedelta(minutes=55, seconds=5)
    )
    assert len(projected["features"]) == 56
    assert projected["evaluation_group_id"] == second["context"]["evaluation_group_id"]
    assert projected["attempt_number"] == 2
    assert projected["source_incident"]["feature_schema_version"] == "features-v3"
    c2unit = next(r for r in plan["runs"] if r["family"] == "c2")
    c2, c2path, c2start = draft_attempt(
        1, c2unit, fixture.COLLECTION_BASE + timedelta(minutes=65, seconds=-20)
    )
    start_run(c2path, source_path, tmp_path, now=c2start)
    network = finish_and_project(c2, fixture.COLLECTION_BASE + timedelta(minutes=65, seconds=5))
    assert network["features"]["http_evidence_available"] == 1
    assert network["features"]["flow_evidence_available"] == 1
    assert len(network["features"]) == 56
    assert network["incident_id"] == network["source_incident"]["incident_id"]
    postbackup = tmp_path.parent / (tmp_path.name + "-post-g7-backup")
    release.create_backup(tmp_path, candidate["tag"], postbackup)
    import tarfile

    with tarfile.open(next(postbackup.glob("collection-*.tar.gz")), "r:gz") as tar:
        assert "evidence/supplemental-acceptance.json" in tar.getnames()
    plan_path.write_text("{}")
    with pytest.raises(release.ReleaseError):
        release.assert_collection_authorized(
            SourceConfig.model_validate(cfg), tmp_path, "trainable", source_path
        )
