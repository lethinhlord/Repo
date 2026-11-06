from collections import Counter
from pathlib import Path

import pytest

from scripts.make_collection_plan import make_plan

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "kind,total", [("pilot", 4), ("minimum", 40), ("preferred", 48), ("challenge", 8)]
)
def test_plan_is_metadata_only_and_has_unique_predeclared_runs(kind, total):
    plan = make_plan(ROOT / "config/scenario-catalog.yaml", kind, 7, "20261106T000000Z")
    assert len(plan["runs"]) == total and plan["telemetry_created"] is False
    assert len({r["run_id"] for r in plan["runs"]}) == total
    assert len({r["collection_seed"] for r in plan["runs"]}) == total
    assert not any("features" in row or "event" in row for row in plan["runs"])
    if kind in {"minimum", "preferred"}:
        counts = Counter(
            r["scenario_id"].split("-")[0] + ":" + r["scenario_id"].split("-")[1]
            for r in plan["runs"]
        )
        assert set(counts.values()) == {10 if kind == "minimum" else 12}
        assert all(r["purpose"] == "trainable" for r in plan["runs"])
