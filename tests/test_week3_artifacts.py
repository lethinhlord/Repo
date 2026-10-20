import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_week3_training_structure_matches_plan() -> None:
    required = [
        "ml/build_dataset.py",
        "ml/train.py",
        "ml/evaluate.py",
        "ml/feature_schema.json",
        "ml/training_config.yaml",
        "ml/model-package/README.md",
        "docs/week3-data-contract.md",
        "docs/week3-model-training-runbook.md",
    ]
    assert all((ROOT / path).is_file() for path in required)


def test_training_config_preserves_60_20_20_grouped_split() -> None:
    config = yaml.safe_load((ROOT / "ml/training_config.yaml").read_text(encoding="utf-8"))

    assert config["random_seed"] == 42
    assert config["data"]["group_key"] == "scenario_id"
    assert config["data"]["require_collection_audit"] is True
    assert config["data"]["scenario_catalog"] == "config/scenario-catalog.yaml"
    assert config["split"] == {
        "train_folds": [0, 1, 2],
        "validation_folds": [3],
        "locked_test_folds": [4],
        "number_of_folds": 5,
    }
    assert set(config["models"]) == {
        "logistic_regression",
        "random_forest",
        "xgboost",
    }


def test_smoke_training_uses_the_same_scenario_group_boundary() -> None:
    config = yaml.safe_load(
        (ROOT / "config/training-smoke.yaml").read_text(encoding="utf-8")
    )

    assert config["data"]["group_key"] == "scenario_id"
    assert config["data"]["minimum_groups_per_family_label"] == 5
    assert config["data"]["require_collection_audit"] is False


def test_feature_schema_excludes_context_and_ground_truth() -> None:
    schema = json.loads((ROOT / "ml/feature_schema.json").read_text(encoding="utf-8"))

    excluded = set(schema["x-excluded-context"])
    assert {
        "threat_intelligence",
        "asset_criticality",
        "scenario_label",
        "ground_truth",
    } <= excluded
    assert set(schema["required"]).isdisjoint(excluded)
