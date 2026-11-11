"""G7 source selection and pilot reuse; all telemetry here is synthetic."""

import json
import shutil

import pytest
import test_official_collection_acceptance as official
import yaml

from ml import collection_release as release
from ml.scenario_collection import SourceConfig


def selected_source(root, original):
    source = root / "operator-logs/collection-sources-active.yaml"
    source.parent.mkdir(exist_ok=True)
    data = yaml.safe_load(original.read_text())
    data["context_baseline_path"] = "evidence/context-next.json"
    shutil.copyfile(root / "evidence/context-baseline.json", root / data["context_baseline_path"])
    source.write_text(yaml.safe_dump(data), encoding="utf-8")
    return source


def test_g7_binds_selected_source_and_trainable_start_uses_it(tmp_path, monkeypatch):
    archive, original, catalog, candidate, old, backup, selected = official.accept_official_lab(
        tmp_path, monkeypatch,
    )
    source = selected_source(tmp_path, original)
    output = tmp_path / "evidence/collection-acceptance.json"
    output.unlink()  # Only the disposable synthetic fixture receipt.
    pilots = [p["run_id"] for p in old["pilots"]]
    accepted = release.create_acceptance(
        tmp_path, candidate["tag"], pilots, backup,
        tmp_path / "operator-logs/preflight/UNIT", output,
        source_config_path=source,
    )
    assert accepted["version"] == "collection-acceptance-v2"
    assert accepted["source_config"]["sha256"] != json.loads(
        (tmp_path / "evidence/scenario-runs" / pilots[0] / ".collection_state.json").read_text()
    )["source_config_sha256"]
    assert release.assert_collection_authorized(
        SourceConfig.model_validate(yaml.safe_load(source.read_text())),
        tmp_path, "trainable", source,
    ) == accepted
    create = official.fixture.create_run_draft

    def draft(*args, **kwargs):
        return create(*args, source_config_path=source, **kwargs)

    monkeypatch.setattr(official.fixture, "create_run_draft", draft)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == selected[0])
    rid = official.fixture._collect_run(
        tmp_path, archive, source, scenario, sequence=4, repeat=7,
    )
    state_path = tmp_path / "evidence/scenario-runs" / rid / ".collection_state.json"
    state = json.loads(state_path.read_text())
    assert state["collection_release"] == accepted
    release.verify_frozen_acceptance(state)
    state["source_config_sha256"] = "f" * 64
    with pytest.raises(release.ReleaseError, match="source"):
        release.verify_frozen_acceptance(state)


@pytest.mark.parametrize("change", [
    "require_online_parity", "feature_scope", "context_baseline_path",
])
def test_selected_source_cannot_change_behavior_or_disable_checks(tmp_path, monkeypatch, change):
    _, original, _, candidate, old, backup, _ = official.accept_official_lab(tmp_path, monkeypatch)
    source = selected_source(tmp_path, original)
    data = yaml.safe_load(source.read_text())
    data[change] = {
        "require_online_parity": False, "feature_scope": "full-window",
        "context_baseline_path": None,
    }[change]
    source.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="source"):
        release.create_acceptance(
            tmp_path, candidate["tag"], [p["run_id"] for p in old["pilots"]], backup,
            tmp_path / "operator-logs/preflight/UNIT", tmp_path / "must-not-exist.json",
            source_config_path=source,
        )
    assert not (tmp_path / "must-not-exist.json").exists()
