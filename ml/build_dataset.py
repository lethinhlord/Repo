from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

from ml.dataset import (
    assign_grouped_folds,
    dataset_hash,
    discover_records,
    load_config,
    load_feature_schema,
    validate_feature_contract,
    write_json,
    write_jsonl,
)
from ml.dataset_audit import audit_dataset


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=False, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def build_dataset(config_path: Path) -> dict[str, object]:
    config = load_config(config_path)
    schema = load_feature_schema(Path(config["feature_schema"]))
    data_config = config["data"]
    audit_summary: dict[str, object] | None = None
    if bool(data_config.get("require_collection_audit", False)):
        report = audit_dataset(
            Path(data_config["raw_dir"]),
            Path(data_config["evidence_dir"]),
            minimum_runs=int(data_config["minimum_runs"]),
            target_runs=int(data_config["target_runs"]),
            minimum_scenarios=int(data_config.get("minimum_scenarios", 5)),
            maximum_scenario_share=float(
                data_config.get("maximum_scenario_share", 0.30)
            ),
            scenario_catalog_path=Path(data_config["scenario_catalog"]),
            source_config_path=Path(
                data_config.get("source_config", "config/collection-sources.yaml")
            ),
            taxonomy_path=Path(
                data_config.get(
                    "taxonomy", "config/suspicious-process-taxonomy.yaml"
                )
            ),
        )
        if report["status"] not in {"READY", "TARGET_MET"}:
            raise ValueError(
                "collection audit is not ready: "
                f"status={report['status']}, errors={report['error_count']}"
            )
        audit_report_path = Path(data_config["audit_report"])
        write_json(audit_report_path, report)
        audit_summary = {
            "status": report["status"],
            "audit_version": report["audit_version"],
            "report_sha256": _sha256(audit_report_path),
            "collection_contract_sha256": report["collection_contract_sha256"],
        }
    records = discover_records(
        Path(data_config["raw_dir"]),
        data_config["manifest_name"],
        data_config["records_name"],
    )
    validate_feature_contract(records, schema)
    number_of_folds = int(config["split"]["number_of_folds"])
    minimum_groups = int(data_config["minimum_groups_per_family_label"])
    group_key = str(data_config.get("group_key", "run_id"))
    if group_key not in {"run_id", "scenario_id"}:
        raise ValueError("data.group_key must be run_id or scenario_id")
    group_strata = {
        getattr(record, group_key): f"{record.family}:{record.label}"
        for record in records
    }
    stratum_counts = Counter(group_strata.values())
    sparse = {name: count for name, count in stratum_counts.items() if count < minimum_groups}
    if sparse:
        raise ValueError(
            f"each family/label requires at least {minimum_groups} independent "
            f"{group_key} groups; "
            f"found {sparse}"
        )
    folds = assign_grouped_folds(
        records,
        number_of_folds=number_of_folds,
        random_seed=int(config["random_seed"]),
        group_key=group_key,
    )
    split_folds = {
        "train": set(config["split"]["train_folds"]),
        "validation": set(config["split"]["validation_folds"]),
        "locked_test": set(config["split"]["locked_test_folds"]),
    }
    if set.union(*split_folds.values()) != set(range(config["split"]["number_of_folds"])):
        raise ValueError("split folds must cover every fold exactly once")
    if sum(len(value) for value in split_folds.values()) != len(set.union(*split_folds.values())):
        raise ValueError("split folds overlap")

    output_dir = Path(data_config["processed_dir"])
    partition_by_run: dict[str, str] = {}
    for run_id, fold in folds.items():
        partition_by_run[run_id] = next(
            name for name, allowed_folds in split_folds.items() if fold in allowed_folds
        )
    for partition in split_folds:
        subset = [row.as_dict() for row in records if partition_by_run[row.run_id] == partition]
        write_jsonl(output_dir / f"{partition}.jsonl", subset)

    split_dir = Path(data_config["splits_dir"])
    file_names = {"train": "train.txt", "validation": "validation.txt", "locked_test": "test.txt"}
    for partition, file_name in file_names.items():
        run_ids = sorted(run_id for run_id, value in partition_by_run.items() if value == partition)
        path = split_dir / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{run_id}\n" for run_id in run_ids), encoding="utf-8")

    manifest = {
        "manifest_version": "dataset-manifest-v2",
        "dataset_hash_sha256": dataset_hash(records),
        "feature_schema_version": schema["version"],
        "feature_schema_sha256": _sha256(Path(config["feature_schema"])),
        "partitions": {
            partition: {
                "sha256": _sha256(output_dir / f"{partition}.jsonl"),
                "record_count": sum(
                    partition_by_run[record.run_id] == partition for record in records
                ),
            }
            for partition in split_folds
        },
        "provenance": {
            "builder_git_commit": _git_commit(),
            "builder_config_sha256": _sha256(config_path),
            "collection_mode": "REAL_LAB" if audit_summary is not None else "SMOKE_ONLY",
            "collection_contract_sha256": (
                audit_summary["collection_contract_sha256"] if audit_summary else None
            ),
        },
        "group_key": group_key,
        "locked_test_status": "UNOPENED",
        "partition_counts": Counter(partition_by_run.values()),
        "record_counts": Counter(partition_by_run[record.run_id] for record in records),
        "stratum_run_counts": Counter(
            f"{record.family}:{record.label}"
            for record in {row.run_id: row for row in records}.values()
        ),
        "split_assignment_commitment_sha256": hashlib.sha256(
            json.dumps(folds, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "locked_test_sha256": _sha256(output_dir / "locked_test.jsonl"),
    }
    if audit_summary is not None:
        manifest["collection_audit"] = audit_summary
    manifest["partition_counts"] = dict(manifest["partition_counts"])
    manifest["record_counts"] = dict(manifest["record_counts"])
    manifest["stratum_run_counts"] = dict(manifest["stratum_run_counts"])
    write_json(output_dir / "dataset_manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build leakage-safe grouped ML partitions")
    parser.add_argument("--config", type=Path, default=Path("ml/training_config.yaml"))
    args = parser.parse_args()
    manifest = build_dataset(args.config)
    print(f"Dataset ready: {manifest['dataset_hash_sha256']}")
    print("Locked test remains UNOPENED.")


if __name__ == "__main__":
    main()
