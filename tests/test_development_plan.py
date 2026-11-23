"""Three-day minimum is a development experiment, never external validation."""

from copy import deepcopy
from datetime import date
from pathlib import Path

import pytest

from ml.supplemental_design import load_design, make_plan, verify_plan
from scripts.supplemental_collection import registration_template

ROOT = Path(__file__).resolve().parents[1]


def development_registration(design):
    result = registration_template(design, date(2026, 12, 1), "Kien")
    for row in result["contexts"]:
        row.update(
            environment_id="WIN11-lab-image-A",
            application_context="idle-lab-session",
            reset_reference="No reset; continuous disposable lab installation",
        )
    return result


def test_three_real_days_generate_48_balanced_development_units():
    design = load_design(ROOT / "config/development-design.yaml")
    plan = make_plan(design, development_registration(design), seed=42)
    verify_plan(plan, design)
    assert len(plan["runs"]) == 48
    assert {r["partition"] for r in plan["runs"]} == {"train"}
    assert {r["context"]["collection_date"] for r in plan["runs"]} == {
        "2026-12-01",
        "2026-12-02",
        "2026-12-03",
    }
    for family in ("account", "c2"):
        for label in ("benign", "malicious"):
            subset = [r for r in plan["runs"] if r["family"] == family and r["label"] == label]
            assert len(subset) == 12
            assert len({r["context"]["evaluation_group_id"] for r in subset}) == 3
        assert len({r["template_id"] for r in plan["runs"] if r["family"] == family}) == (
            5 if family == "account" else 4
        )


@pytest.mark.parametrize("mutation", ["one-day", "four-days", "role", "missing", "smaller"])
def test_development_cannot_fake_days_roles_or_quota(mutation):
    design = load_design(ROOT / "config/development-design.yaml")
    registration = development_registration(design)
    if mutation == "one-day":
        for row in registration["contexts"]:
            row["collection_date"] = "2026-12-01"
    elif mutation == "four-days":
        registration["contexts"][-1]["collection_date"] = "2026-12-04"
    elif mutation == "role":
        registration["contexts"][0]["partition"] = "validation"
    elif mutation == "missing":
        registration["contexts"].pop()
    else:
        design = deepcopy(design)
        design["partition_contexts"]["train"] = 4
    with pytest.raises(ValueError):
        make_plan(design, registration, seed=42)


def test_formal_design_still_requires_its_original_registration():
    formal = load_design(ROOT / "config/supplemental-design.yaml")
    registration = development_registration(formal)
    assert len(make_plan(formal, registration, seed=42)["runs"]) == 216
