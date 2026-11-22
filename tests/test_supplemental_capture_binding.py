"""New campaign bindings; fixtures are protocol tests, never lab acceptance."""

import random
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from test_collection_acceptance import _clock_preflight
from test_supplemental_plan import registration

from ml.execution_profile import freeze_execution_profile
from ml.scenario_collection import (
    CollectionError,
    RunDraft,
    ScenarioCatalog,
    _validate_campaign_date,
    _validate_draft_against_catalog,
)
from ml.supplemental_catalog import compile_catalog
from ml.supplemental_design import load_design, make_plan

ROOT = Path(__file__).resolve().parents[1]


def campaign_fixture(tmp_path, family="account", cohort_id=None):
    d = load_design(ROOT / "config/supplemental-design.yaml")
    catalog = compile_catalog(
        d, yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_text())
    )
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump(catalog), encoding="utf-8")
    plan = make_plan(d, registration(d), seed=42)
    row = next(
        r
        for r in plan["runs"]
        if r["family"] == family and (cohort_id is None or r["cohort_id"] == cohort_id)
    )
    scenario = next(
        s
        for s in ScenarioCatalog.model_validate(catalog).scenarios
        if s.scenario_id == row["scenario_id"]
    )
    rng = random.Random(row["collection_seed"])
    common = {"pre_action_delay_seconds": round(rng.uniform(1, 5), 3)}
    draft = RunDraft(
        scenario_id=scenario.scenario_id,
        run_id=row["run_id"],
        family=scenario.family,
        label=scenario.label,
        cohort_id=scenario.cohort_id,
        host=row["context"]["host"],
        operator=row["context"]["operator"],
        expected_behavior=scenario.expected_behavior,
        attribution=scenario.attribution,
        quality_gates=scenario.quality_gates,
        collection_seed=row["collection_seed"],
        expected_observables=scenario.expected_observables,
        clock_preflight=_clock_preflight(datetime(2027, 1, 1, tzinfo=UTC)),
        scenario_parameters=freeze_execution_profile(
            scenario.execution_profile, rng, common, row["run_id"], row["collection_seed"]
        ),
        campaign_plan=plan,
    )
    return path, draft


def test_campaign_draft_binds_full_plan_and_actual_utc_date(tmp_path):
    path, draft = campaign_fixture(tmp_path)
    _validate_draft_against_catalog(draft, path)
    day = draft.campaign_plan["runs"][0]["context"]["collection_date"]
    at = datetime.fromisoformat(day).replace(tzinfo=UTC)
    _validate_campaign_date(draft, at)
    with pytest.raises(CollectionError, match="registered UTC date"):
        _validate_campaign_date(draft, at + timedelta(days=1))


@pytest.mark.parametrize(
    "field,value",
    [
        ("campaign_plan", None),
        ("run_id", "unplanned-run"),
        ("host", "OTHER-HOST"),
        ("operator", "other operator"),
        ("purpose", "pilot"),
    ],
)
def test_campaign_cannot_bypass_plan_row(tmp_path, field, value):
    path, draft = campaign_fixture(tmp_path)
    draft = draft.model_copy(update={field: value})
    with pytest.raises(CollectionError):
        _validate_draft_against_catalog(draft, path)


def test_coordinated_catalog_changes_fail_source_check(tmp_path):
    from shutil import copyfile

    from ml.collection_release import ReleaseError, _check_design

    (tmp_path / "config").mkdir()
    for name in ("supplemental-design.yaml", "scenario-catalog.yaml"):
        copyfile(ROOT / "config" / name, tmp_path / "config" / name)
    design = load_design(tmp_path / "config/supplemental-design.yaml")
    catalog = compile_catalog(
        design, yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_text())
    )
    path = tmp_path / "config/supplemental-catalog.yaml"
    source = tmp_path / "config/source.yaml"
    source.write_text(yaml.safe_dump({"scenario_catalog_path": "config/supplemental-catalog.yaml"}))
    path.write_text(yaml.safe_dump(catalog))
    _check_design(tmp_path, source)
    altered = deepcopy(catalog)
    altered["template_definitions"]["account-recovery:benign"]["quality_gates"][
        "min_account_failures"
    ] = 0
    for row in altered["scenarios"]:
        if row.get("template_id") == "account-recovery" and row["label"] == "benign":
            row["quality_gates"]["min_account_failures"] = 0
    path.write_text(yaml.safe_dump(altered))
    with pytest.raises(ReleaseError):
        _check_design(tmp_path, source)


def http_events(tmp_path, cohort_id=None):
    import json

    from test_collection_acceptance import _c2_events
    from test_official_collection_acceptance import _native

    from ml.http_workflow import action_rows
    from ml.scenario_collection import SourceConfig

    path, draft = campaign_fixture(tmp_path, "c2", cohort_id)
    scenario = next(
        s
        for s in ScenarioCatalog.model_validate(yaml.safe_load(path.read_text())).scenarios
        if s.scenario_id == draft.scenario_id
    )
    events, _ = _c2_events(
        draft.run_id, scenario, draft, datetime(2027, 1, 1, 0, 0, 10, tzinfo=UTC)
    )
    actions = action_rows(draft.scenario_parameters)
    for event in events:
        if "full_log" not in event:
            _native(event)
            continue
        payload = json.loads(event["full_log"])
        number = int(payload["flow_id"].rsplit("-", 1)[-1])
        method, sent, received = actions[number]
        if payload["event_type"] == "http":
            payload["http"].update(http_method=method, length=received)
            payload["http"]["url"] += f"&z={received}"
        elif payload["event_type"] == "flow":
            payload["flow"].update(bytes_toserver=sent + 300, bytes_toclient=received + 200)
        event["full_log"] = json.dumps(payload)
    source = SourceConfig.model_validate(
        yaml.safe_load((ROOT / "config/collection-sources.yaml").read_text())
    )
    return draft, source, events


@pytest.mark.parametrize("mutation", [None, "method", "size", "ordinal", "short-upload"])
def test_actual_collector_enforces_v2_wire_contract(tmp_path, mutation):
    import json

    from ml.scenario_collection import _derive_c2

    draft, source, events = http_events(tmp_path)
    taxonomy = yaml.safe_load((ROOT / "config/suspicious-process-taxonomy.yaml").read_text())
    if mutation:
        for event in events:
            if "full_log" not in event:
                continue
            payload = json.loads(event["full_log"])
            if mutation == "short-upload" and payload["event_type"] == "flow":
                payload["flow"]["bytes_toserver"] = 0
            elif payload["event_type"] == "http":
                if mutation == "method":
                    payload["http"]["http_method"] = "DELETE"
                elif mutation == "size":
                    payload["http"]["length"] += 1
                elif mutation == "ordinal":
                    payload["http"]["url"] = payload["http"]["url"].replace("n=1&", "n=99&")
            event["full_log"] = json.dumps(payload)
    if mutation:
        with pytest.raises(CollectionError, match="HTTP"):
            _derive_c2(events, draft, source, taxonomy)
    else:
        features, native, eve, _ = _derive_c2(events, draft, source, taxonomy)
        assert native and eve and features
