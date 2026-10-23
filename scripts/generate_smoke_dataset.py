from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ml.behavior_features import empty_feature_vector


def generate(output_dir: Path, *, random_seed: int = 42) -> None:
    rng = random.Random(random_seed)
    started = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
    for family in ("account", "c2"):
        for label_name, label in (("benign", 0), ("malicious", 1)):
            for run_number in range(10):
                run_id = f"SMOKE-{family.upper()}-{label_name.upper()}-{run_number:02d}"
                scenario_number = run_number % 5
                run_dir = output_dir / run_id
                run_dir.mkdir(parents=True, exist_ok=True)
                manifest = {
                    "scenario_id": (
                        f"SMOKE-{family.upper()}-{label_name.upper()}-S{scenario_number:02d}"
                    ),
                    "run_id": run_id,
                    "family": family,
                    "label": label_name,
                    "host": f"SMOKE-{family.upper()}-HOST",
                    "start_time": (started + timedelta(hours=run_number)).isoformat(),
                    "end_time": (started + timedelta(hours=run_number, minutes=5)).isoformat(),
                    "expected_behavior": (
                        "Synthetic pipeline smoke test only; never use for evaluation claims."
                    ),
                    "collection_seed": random_seed + run_number,
                    "scenario_parameters": {
                        "synthetic_noise_seed": random_seed + run_number,
                        "variant_index": run_number,
                    },
                    "provenance_sha256": "0" * 64,
                }
                (run_dir / "scenario_manifest.json").write_text(
                    json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
                )
                records = []
                for incident_number in range(4):
                    noise = rng.uniform(-0.25, 0.25)
                    features = empty_feature_vector()
                    if family == "account":
                        features.update(
                            {
                                "failed_login_count": max(
                                    0.0, (3.0 if not label else 18.0) + noise
                                ),
                                "successful_login_count": float(
                                    incident_number % 2 == 0
                                ),
                                "success_after_fail": float(
                                    label and incident_number % 2 == 0
                                ),
                                "unique_target_account_count": float(1 + label),
                                "unique_source_count": float(1 + label),
                                "remote_logon_ratio": float(label) * 0.75,
                                "failure_window_seconds": float(
                                    (incident_number + 1) * (10 if not label else 45)
                                ),
                                "attempt_rate_per_minute": max(
                                    0.0, (2.0 if not label else 12.0) + noise
                                ),
                            }
                        )
                    else:
                        features.update(
                            {
                                "suspicious_process": float(label),
                                "periodicity_score": max(
                                    0.0, (0.12 if not label else 0.86) + noise / 5
                                ),
                                "connection_interval_cv": max(
                                    0.0, (0.9 if not label else 0.1) + noise / 5
                                ),
                                "mean_interval_seconds": float(
                                    30 if not label else 15
                                ),
                                "suricata_alert_count": float(label * 2),
                                "suricata_severity_score": float(label) * 0.66,
                                "outbound_connection_count": max(
                                    0.0, (3.0 if not label else 35.0) + noise
                                ),
                                "unique_destination_count": float(
                                    2 if not label else 5
                                ),
                                "destination_port_count": float(
                                    2 if not label else 12
                                ),
                                "dns_query_count": float(incident_number),
                                "dns_unique_query_ratio": 1.0,
                                "flow_total_bytes_log1p": float(
                                    5 if not label else 9
                                ),
                            }
                        )
                    incident_time = started + timedelta(hours=run_number, minutes=incident_number)
                    records.append(
                        {
                            "incident": {
                                "incident_id": f"{run_id}-{incident_number:02d}",
                                "asset_id": manifest["host"],
                                "start_time": incident_time.isoformat(),
                                "end_time": incident_time.isoformat(),
                                "family_hint": family,
                                "features": features,
                                "evidence_sources": ["smoke-generator"],
                                "base_severity": 3 if not label else 12,
                                "raw_refs": [f"smoke:{run_id}:{incident_number}"],
                                "indicator": None,
                            }
                        }
                    )
                (run_dir / "incidents.jsonl").write_text(
                    "".join(json.dumps(record) + "\n" for record in records),
                    encoding="utf-8",
                )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate non-scientific Week 3 smoke data")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/runtime/smoke-data/raw"))
    args = parser.parse_args()
    generate(args.output_dir)
    print(f"SMOKE_ONLY dataset generated at {args.output_dir}")


if __name__ == "__main__":
    main()
