"""Regression contracts from the 2026-11-07 independent audit."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from api.app.contracts import IncidentRequest
from ml.dataset import discover_records
from ml.dataset_audit import audit_dataset
from scripts.generate_smoke_dataset import generate

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("overrides", [
    {"minimum_runs": 5, "target_runs": 5},
    {"minimum_runs": 5},
    {"minimum_scenarios": 1},
])
def test_official_design_refuses_alternative_quota(tmp_path, overrides):
    with pytest.raises(ValueError, match="design.*quota"):
        audit_dataset(
            tmp_path/"raw", tmp_path/"evidence",
            scenario_catalog_path=ROOT/"config/scenario-catalog.yaml",
            source_config_path=ROOT/"config/collection-sources.yaml",
            taxonomy_path=ROOT/"config/suspicious-process-taxonomy.yaml",
            **overrides,
        )


def test_seed_reuse_across_labels_is_not_accepted(tmp_path, monkeypatch):
    import test_dataset_audit as fixture

    from ml import dataset_audit

    fixture.populate(tmp_path)
    original = dataset_audit._audit_run

    def matching_seed(*args, **kwargs):
        manifest, incidents, errors = original(*args, **kwargs)
        if manifest is not None:
            # Isolate cross-stratum uniqueness after independently validating each
            # fixture's evidence; no on-disk source evidence is edited.
            manifest.collection_seed = int(manifest.run_id.rsplit("-", 1)[1])
        return manifest, incidents, errors

    monkeypatch.setattr(dataset_audit, "_audit_run", matching_seed)
    report = fixture.run_audit(tmp_path)
    assert report["status"] == "NOT_READY"
    assert any(i["code"] == "COLLECTION_SEED_REUSE" for i in report["issues"])


def test_discovery_preserves_incident_context_for_challenge_replay(tmp_path):
    generate(tmp_path/"raw")
    manifest = next((tmp_path/"raw").glob("*/scenario_manifest.json"))
    doc = json.loads(manifest.read_text())
    doc["purpose"] = "challenge"
    manifest.write_text(json.dumps(doc), encoding="utf-8")
    records_file = manifest.with_name("incidents.jsonl")
    payload = json.loads(records_file.read_text().splitlines()[0])
    expected = IncidentRequest.model_validate(
        payload.get("incident", payload)
    ).model_dump(mode="json")
    rows = discover_records(tmp_path/"raw", "scenario_manifest.json", "incidents.jsonl",
                            include_purposes=("challenge",))
    assert rows[0].as_dict()["incident"] == expected
    assert rows[0].as_dict()["features"] == expected["features"]


def test_declared_design_quota_is_complete_and_strict():
    from ml.collection_design import load_collection_design
    doc = yaml.safe_load((ROOT/"config/collection-design.yaml").read_text())
    assert load_collection_design(ROOT/"config/scenario-catalog.yaml")["quota"] == doc["quota"]
