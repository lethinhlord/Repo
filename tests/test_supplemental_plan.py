"""Prospective metadata only: these tests never manufacture training telemetry."""

from copy import deepcopy
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def registration(design):
    contexts = []
    day = date(2027, 1, 1)
    # Both families on a host/day share the same role and dependency block.
    for family in ("account", "c2"):
        for i, role in enumerate(["train"] * 10 + ["validation"] * 4 + ["locked_test"] * 4):
            contexts.append(
                dict(
                    cohort_id=f"{family.upper()}-SUP-{i + 1:02d}",
                    collection_date=(day + timedelta(days=i)).isoformat(),
                    environment_id="WIN11-LAB-IMAGE-A",
                    host="WIN11-TARGET",
                    application_context=f"Approved lab context {i + 1}",
                    reset_reference=f"Lab reset record {i + 1}",
                    operator="Kien",
                    partition=role,
                )
            )
    return {
        "version": "supplemental-registration-v1",
        "campaign_id": design["campaign_id"],
        "contexts": contexts,
    }


def test_plan_freezes_complete_inventory_and_named_roles(tmp_path):
    from ml.supplemental_design import load_design, make_plan, verify_plan

    design = load_design(ROOT / "config/supplemental-design.yaml")
    registered = registration(design)
    plan = make_plan(design, registered, seed=42)
    verify_plan(plan, design)
    assert len(plan["runs"]) == 216
    assert {f: sum(r["family"] == f for r in plan["runs"]) for f in ("account", "c2")} == {
        "account": 108,
        "c2": 108,
    }
    assert {
        role: sum(r["partition"] == role for r in plan["runs"])
        for role in ("train", "validation", "locked_test")
    } == {"train": 120, "validation": 48, "locked_test": 48}
    assert len({r["run_id"] for r in plan["runs"]}) == 216
    assert len({r["collection_seed"] for r in plan["runs"]}) == 216
    assert make_plan(design, registered, seed=42) == plan
    assert any(
        r["template_id"] == plan["runs"][0]["template_id"]
        and r["cohort_id"] != plan["runs"][0]["cohort_id"]
        for r in plan["runs"]
    )


@pytest.mark.parametrize("mutation", ["role", "template", "duplicate", "seed", "registration"])
def test_plan_rehash_cannot_change_design_or_registered_membership(mutation):
    from ml.supplemental_design import load_design, make_plan, verify_plan
    from ml.training_sources import digest

    d = load_design(ROOT / "config/supplemental-design.yaml")
    p = make_plan(d, registration(d), seed=42)
    if mutation == "role":
        p["runs"][0]["partition"] = "locked_test"
    elif mutation == "template":
        p["runs"][0]["template_id"] = "fabricated"
    elif mutation == "duplicate":
        p["runs"][1] = deepcopy(p["runs"][0])
    elif mutation == "seed":
        p["runs"][0]["collection_seed"] = 0
    else:
        p["registration"]["contexts"][0]["reset_reference"] = "changed later"
    p["plan_sha256"] = digest({k: v for k, v in p.items() if k != "plan_sha256"})
    with pytest.raises(ValueError):
        verify_plan(p, d)


@pytest.mark.parametrize("mutation", ["same-day-role", "missing", "placeholder", "too-few-blocks"])
def test_registration_refuses_fake_or_overlapping_contexts(mutation):
    from ml.supplemental_design import load_design, make_plan

    d = load_design(ROOT / "config/supplemental-design.yaml")
    r = registration(d)
    if mutation == "same-day-role":
        r["contexts"][10]["collection_date"] = r["contexts"][0]["collection_date"]
    elif mutation == "missing":
        r["contexts"].pop()
    elif mutation == "placeholder":
        r["contexts"][0]["environment_id"] = "TODO"
    else:
        for row in r["contexts"][10:14]:
            row["collection_date"] = "2027-01-11"
    with pytest.raises(ValueError):
        make_plan(d, r, seed=42)
