"""Predeclared observable targets and confounders; never inferred from labels."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from ml.behavior_features import ACCOUNT_FEATURES, C2_FEATURES

NUISANCE = {
    "account": {"remote_logon_ratio", "source_history_known", "new_source_for_user"},
    "c2": {
        "suspicious_process",
        "destination_port_count",
        "destination_history_known",
        "new_destination",
        "suricata_severity_score",
    },
}


def load_collection_design(catalog_path: Path) -> dict[str, Any] | None:
    path = catalog_path.parent / "collection-design.yaml"
    if not path.exists():
        return None
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (
        not isinstance(doc, dict)
        or doc.get("version") != "collection-design-v1"
        or doc.get("group_key") != "cohort_id"
        or doc.get("feature_count") != 24
        or doc.get("automation_eligible") is not False
    ):
        raise ValueError("invalid collection design identity, feature or automation contract")
    quota = doc.get("quota")
    required_quota = (
        "minimum_runs_per_stratum", "target_runs_per_stratum",
        "minimum_scenarios_per_stratum", "minimum_cohorts_per_stratum",
        "minimum_repetitions_per_scenario",
    )
    if (
        not isinstance(quota, dict)
        or any(type(quota.get(key)) is not int or quota[key] < 1 for key in required_quota)
        or quota["target_runs_per_stratum"] < quota["minimum_runs_per_stratum"]
        or quota["minimum_cohorts_per_stratum"] < 5
        or quota["minimum_runs_per_stratum"] < (
            quota["minimum_scenarios_per_stratum"] * quota["minimum_repetitions_per_scenario"]
        )
    ):
        raise ValueError("invalid collection design quota")
    extras = quota.get("target_extra_repetition_cohort_suffixes")
    if (
        not isinstance(extras, list)
        or any(not isinstance(suffix, str) or not suffix for suffix in extras)
        or len(set(extras)) != len(extras)
        or quota["target_runs_per_stratum"] != (
            quota["minimum_repetitions_per_scenario"] * quota["minimum_scenarios_per_stratum"]
            + len(extras)
        )
    ):
        raise ValueError("invalid collection design quota target cohort allocation")
    policy = doc.get("audit_policy", {})
    if any(
        policy.get(k) != v
        for k, v in {
            "nuisance_separation": "ERROR",
            "behavioral_separation": "WARNING",
            "cross_label_collision": "ERROR",
            "forbidden_feature": "ERROR",
        }.items()
    ):
        raise ValueError("collection design cannot weaken collision or nuisance checks")
    for family, features in (("account", ACCOUNT_FEATURES), ("c2", C2_FEATURES)):
        nuisance = set(policy.get("nuisance_features", {}).get(family, []))
        behavior = set(policy.get("behavioral_features", {}).get(family, []))
        if (
            nuisance != NUISANCE[family]
            or nuisance & behavior
            or nuisance | behavior != set(features)
        ):
            raise ValueError("design must partition all features into fixed semantic roles")
    return {**doc, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def separation_severity(design: dict | None, family: str, features: set[str]) -> str:
    # Perfect behavioral separation is a diagnostic, not itself evidence of label
    # leakage: learning such relationships is the declared prediction task. Source
    # identity/tool/context confounders still block acceptance, alone or jointly.
    if design is not None and not features <= NUISANCE[family]:
        return "WARNING"
    return "ERROR"
