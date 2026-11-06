"""Collection design checks establish feasibility, never observed lab acceptance."""

from collections import defaultdict
from pathlib import Path

import pytest
import yaml

from ml.behavior_features import ACCOUNT_FEATURES, C2_FEATURES, FEATURE_ORDER
from ml.dataset import DatasetRecord, assign_grouped_folds
from ml.scenario_collection import ScenarioCatalog

ROOT = Path(__file__).resolve().parents[1]


def _documents():
    catalog = yaml.safe_load((ROOT / "config/scenario-catalog.yaml").read_text())
    design = yaml.safe_load((ROOT / "config/collection-design.yaml").read_text())
    return catalog, design


def test_design_preserves_feature_and_quota_contract():
    _, design = _documents()
    config = yaml.safe_load((ROOT / "ml/training_config.yaml").read_text())
    assert len(FEATURE_ORDER) == design["feature_count"] == 24
    assert config["data"]["minimum_runs"] == 10
    assert config["data"]["target_runs"] == 12
    assert config["data"]["minimum_scenarios"] == 5
    assert config["data"]["minimum_groups_per_family_label"] == 5
    assert config["data"]["group_key"] == design["group_key"] == "cohort_id"
    assert config["data"]["collection_design"] == "config/collection-design.yaml"
    assert design["automation_eligible"] is False
    for family, features in (("account", ACCOUNT_FEATURES), ("c2", C2_FEATURES)):
        nuisance = set(design["audit_policy"]["nuisance_features"][family])
        behavioral = set(design["audit_policy"]["behavioral_features"][family])
        assert not nuisance & behavioral
        assert nuisance | behavioral == set(features)


def test_catalog_validates_and_matched_pairs_share_nuisance_entities():
    catalog, design = _documents()
    parsed = ScenarioCatalog.model_validate(catalog)
    assert len(parsed.scenarios) == 28
    by_cohort = defaultdict(list)
    for row in catalog["scenarios"]:
        if row["purpose"] == "trainable":
            by_cohort[row["cohort_id"]].append(row)
    assert set(by_cohort) == {row["cohort_id"] for row in design["cohorts"]}
    for pair in by_cohort.values():
        assert len(pair) == 2
        assert {row["label"] for row in pair} == {"benign", "malicious"}
        assert pair[0]["attribution"] == pair[1]["attribution"]
        first, second = (row["execution_profile"] for row in pair)
        for key in ("transport", "accounts_csv", "endpoint", "domain_suffix", "dns_server"):
            assert first.get(key) == second.get(key)
        for key in ("required_suricata_signature_ids", "forbidden_suricata_signature_ids"):
            assert pair[0]["quality_gates"].get(key) == pair[1]["quality_gates"].get(key)


def test_frozen_schedules_are_finite_bounded_and_account_receipts_are_exact():
    catalog, _ = _documents()
    for row in catalog["scenarios"]:
        profile = row["execution_profile"]
        gaps = [float(value) for value in profile["base_intervals_seconds"].split(",") if value]
        assert len(gaps) == profile["expected_action_count"] - 1
        assert all(1 <= gap <= 300 for gap in gaps)
        # Collection still checks real startup/reserve against the action bucket.
        assert sum(gaps) * 1.3 < 240
        if row["family"] == "account":
            attempts = profile["attempts_csv"].split(",")
            assert len(attempts) == profile["expected_action_count"]
            failures = sum(item.endswith(":fail") for item in attempts)
            successes = sum(item.endswith(":success") for item in attempts)
            gates = row["quality_gates"]
            assert failures == gates["min_account_failures"] == gates["max_account_failures"]
            assert successes == gates["min_account_successes"] == gates["max_account_successes"]
            assert {item.split(":")[0] for item in attempts} == set(
                profile["accounts_csv"].split(",")
            )


@pytest.mark.parametrize("target", [False, True])
def test_exact_planned_repetitions_support_all_five_outer_and_three_inner_groups(target):
    catalog, design = _documents()
    cohort_config = {item["cohort_id"]: item for item in design["cohorts"]}
    records = []
    strata = defaultdict(list)
    for row in catalog["scenarios"]:
        if row["purpose"] != "trainable":
            continue
        cohort = cohort_config[row["cohort_id"]]
        count = cohort["target_runs_per_scenario" if target else "minimum_runs_per_scenario"]
        for repeat in range(count):
            run = f"{row['scenario_id']}-R{repeat}"
            record = DatasetRecord(
                incident_id=run,
                run_id=run,
                scenario_id=row["scenario_id"],
                family=row["family"],
                label=int(row["label"] == "malicious"),
                features={},
                source_file="design-only-not-evidence",
                cohort_id=row["cohort_id"],
            )
            records.append(record)
            strata[(record.family, record.label)].append(record)
    assert len(records) == (48 if target else 40)
    assert all(len(rows) == (12 if target else 10) for rows in strata.values())
    folds = assign_grouped_folds(records, number_of_folds=5, random_seed=42, group_key="cohort_id")
    all_strata = {(family, label) for family in ("account", "c2") for label in (0, 1)}
    for fold in range(5):
        assert {
            (row.family, row.label) for row in records if folds[row.run_id] == fold
        } == all_strata
    cohort_folds = defaultdict(set)
    for row in records:
        cohort_folds[row.cohort_id].add(folds[row.run_id])
    assert all(len(values) == 1 for values in cohort_folds.values())
    for family, label in all_strata:
        assert (
            len(
                {
                    row.cohort_id
                    for row in records
                    if row.family == family
                    and row.label == label
                    and folds[row.run_id] in {0, 1, 2}
                }
            )
            == 3
        )
        assert (
            len(
                {
                    row.cohort_id
                    for row in records
                    if row.family == family and row.label == label and folds[row.run_id] == 3
                }
            )
            == 1
        )


def test_intent_challenges_are_paired_review_only_and_not_independent_training_cohorts():
    catalog, design = _documents()
    rows = [row for row in catalog["scenarios"] if row["purpose"] == "challenge"]
    expected = {row["scenario_id"]: row for row in design["challenge_expectations"]}
    assert len(rows) == len(expected) == 8
    pairs = defaultdict(list)
    train_cohorts = {
        row["cohort_id"] for row in catalog["scenarios"] if row["purpose"] == "trainable"
    }
    for row in rows:
        assert expected[row["scenario_id"]]["expected_decision"] == "REVIEW"
        assert expected[row["scenario_id"]]["training_eligible"] is False
        assert row["cohort_id"] in train_cohorts
        pairs[row["scenario_id"].rsplit("-", 1)[0]].append(row)
    for pair in pairs.values():
        assert {row["label"] for row in pair} == {"benign", "malicious"}
        assert pair[0]["execution_profile"] == pair[1]["execution_profile"]
        assert pair[0]["attribution"] == pair[1]["attribution"]
        assert pair[0]["cohort_id"] == pair[1]["cohort_id"]
