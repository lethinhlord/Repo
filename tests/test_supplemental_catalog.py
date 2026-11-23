from copy import deepcopy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_compiled_catalog_keeps_templates_distinct_from_context_instances():
    from ml.scenario_collection import ScenarioCatalog
    from ml.supplemental_catalog import compile_catalog, validate_catalog
    from ml.supplemental_design import load_design

    d = load_design(ROOT / "config/supplemental-design.yaml")
    old = yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_text())
    catalog = compile_catalog(d, old)
    validate_catalog(catalog)
    parsed = ScenarioCatalog.model_validate(catalog)
    assert parsed.version == "scenario-catalog-v2"
    assert len(parsed.scenarios) == 84
    train = [s for s in parsed.scenarios if s.purpose == "trainable"]
    assert len(train) == 72 and len({s.cohort_id for s in train}) == 36
    assert len({s.template_id for s in train}) == 9
    for row in train:
        if row.family == "c2":
            assert row.execution_profile["profile_version"] == "lab-http-workflow-v2"
    assert len([s for s in parsed.scenarios if s.purpose == "pilot"]) == 4
    assert len([s for s in parsed.scenarios if s.purpose == "challenge"]) == 8


@pytest.mark.parametrize("change", ["profile", "template", "role", "pilot", "nuisance"])
def test_catalog_cannot_drift_from_declared_template_pair(change):
    from ml.supplemental_catalog import compile_catalog, validate_catalog
    from ml.supplemental_design import load_design

    d = load_design(ROOT / "config/supplemental-design.yaml")
    c = compile_catalog(d, yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_text()))
    c = deepcopy(c)
    if change == "profile":
        c["scenarios"][0]["execution_profile"]["expected_action_count"] = 1
    elif change == "template":
        c["scenarios"][0]["template_id"] = "other"
    elif change == "role":
        c["scenarios"][0]["cohort_id"] = "other"
    elif change == "pilot":
        c["scenarios"] = [x for x in c["scenarios"] if x["purpose"] != "pilot"]
    else:
        c["scenarios"][0]["attribution"]["source_ips"] = ["192.0.2.1"]
    with pytest.raises(ValueError):
        validate_catalog(c)
