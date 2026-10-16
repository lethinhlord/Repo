from __future__ import annotations

import argparse
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


def build_dataset(config_path: Path) -> dict[str, object]:
    config = load_config(config_path)
    schema = load_feature_schema(Path(config["feature_schema"]))
    data_config = config["data"]
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
        "dataset_hash_sha256": dataset_hash(records),
        "feature_schema_version": schema["version"],
        "group_key": group_key,
        "locked_test_status": "UNOPENED",
        "partition_counts": Counter(partition_by_run.values()),
        "record_counts": Counter(partition_by_run[record.run_id] for record in records),
        "stratum_run_counts": Counter(
            f"{record.family}:{record.label}"
            for record in {row.run_id: row for row in records}.values()
        ),
        "fold_by_run": folds,
    }
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
