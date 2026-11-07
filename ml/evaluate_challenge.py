"""Post-freeze challenge replay. Never supplies labels or expected decisions to inference."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from api.app.contracts import IncidentRequest
from ml.evaluate import _atomic_write
from ml.evaluation_evidence import runtime_policy_hash
from ml.freeze_model import file_hash, sign_evidence
from ml.inference import ModelRuntime


def evaluate_challenge(
    package_dir: Path,
    challenge_path: Path,
    manifest_path: Path,
    design_path: Path,
    *,
    evidence_dir: Path | None = None,
) -> dict[str, Any]:
    runtime = ModelRuntime(package_dir, evidence_dir=evidence_dir)
    metadata = runtime.metadata
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_hash = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if manifest_hash != metadata.get("dataset_manifest_payload_sha256"):
        raise ValueError("challenge dataset manifest differs from frozen training commitment")
    design_hash = file_hash(design_path)
    if design_hash != metadata.get("dataset_provenance", {}).get("collection_design_sha256"):
        raise ValueError("challenge collection design differs from frozen policy")
    policy_hash = runtime_policy_hash()
    if policy_hash != metadata.get("runtime_policy_sha256"):
        raise ValueError("challenge runtime policy differs from frozen training policy")
    design = yaml.safe_load(design_path.read_text(encoding="utf-8"))
    policy = design.get("challenge_evaluation", {})
    if (
        policy.get("post_freeze_only") is not True
        or policy.get("threshold_tuning_allowed") is not False
    ):
        raise ValueError("challenge policy must require post-freeze evaluation without tuning")
    expected = {row["scenario_id"]: row for row in design["challenge_expectations"]}
    if (
        not expected
        or len(expected) != len(design["challenge_expectations"])
        or any(
            row.get("expected_decision") != "REVIEW" or row.get("training_eligible") is not False
            for row in expected.values()
        )
    ):
        raise ValueError("invalid challenge expectation contract")
    commitment = manifest.get("challenge", {})
    if commitment.get("training_eligible") is not False or commitment.get("record_count", 0) < 1:
        raise ValueError("challenge commitment is empty or training eligible")
    evidence = runtime.evidence_dir
    evidence.mkdir(parents=True, exist_ok=True)
    reservation = evidence / "CHALLENGE_RESERVED"
    report_path = evidence / "challenge_evaluation.json"
    if report_path.exists() or report_path.is_symlink():
        raise PermissionError("challenge evaluation already completed")
    try:
        _atomic_write(
            reservation,
            sign_evidence(
                {
                    "status": "RESERVED",
                    "freeze_sha256": file_hash(package_dir / "FROZEN.json"),
                    "dataset_manifest_payload_sha256": manifest_hash,
                    "challenge_sha256": commitment["sha256"],
                    "runtime_policy_sha256": policy_hash,
                    "collection_design_sha256": design_hash,
                }
            ),
        )
    except FileExistsError as exc:
        raise PermissionError("challenge evaluation already opened or reserved") from exc
    # No challenge bytes are accessed until the reservation is durably published.
    payload = challenge_path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != commitment.get("sha256"):
        raise ValueError("challenge integrity check failed; preserve reservation")
    rows = [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]
    if len(rows) != commitment["record_count"]:
        raise ValueError("challenge record count mismatch")
    records = []
    pairs: dict[str, list[str]] = defaultdict(list)
    seen = set()
    for row in rows:
        scenario = row.get("scenario_id")
        expectation = expected.get(scenario)
        if (
            row.get("purpose") != "challenge"
            or expectation is None
            or row.get("cohort_id") != expectation.get("cohort_id")
        ):
            raise ValueError("challenge row does not match approved scenario/cohort")
        identity = (row.get("run_id"), row.get("incident_id"))
        if identity in seen:
            raise ValueError("duplicate challenge incident")
        seen.add(identity)
        if not isinstance(row.get("incident"), dict):
            raise ValueError("challenge replay requires preserved runtime incident context")
        incident = IncidentRequest.model_validate(row["incident"])
        if (
            incident.features != row.get("features")
            or incident.family_hint != row.get("family")
            or incident.incident_id != row.get("incident_id")
        ):
            raise ValueError("challenge runtime payload disagrees with dataset record")
        prediction = runtime.predict(incident)
        decision = "REVIEW" if prediction.review_required else prediction.predicted_class.upper()
        pairs[row["cohort_id"]].append(decision)
        records.append(
            {
                "scenario_id": scenario,
                "cohort_id": row["cohort_id"],
                "run_id": row["run_id"],
                "incident_id": row["incident_id"],
                "expected_decision": expectation["expected_decision"],
                "actual_decision": decision,
                "matched": decision == expectation["expected_decision"],
                **prediction.model_dump(mode="json"),
            }
        )
    covered = {row["scenario_id"] for row in records}
    count = len(records)
    coverage = len(covered) / len(expected)
    # Pair agreement compares scenario decision distributions, not row order or run count.
    pair_results = []
    for cohort in pairs:
        distributions = []
        for scenario in sorted(key for key in covered if expected[key]["cohort_id"] == cohort):
            decisions = [
                row["actual_decision"] for row in records if row["scenario_id"] == scenario
            ]
            distributions.append(
                tuple(
                    decisions.count(value) / len(decisions)
                    for value in ("REVIEW", "BENIGN", "MALICIOUS")
                )
            )
        if len(distributions) >= 2:
            pair_results.append(len(set(distributions)) == 1)
    output = {
        "status": "PASS" if coverage == 1 and all(row["matched"] for row in records) else "FAIL",
        "model_version": metadata["model_version"],
        "evaluated_at_utc": datetime.now(UTC).isoformat(),
        "freeze_sha256": file_hash(package_dir / "FROZEN.json"),
        "dataset_manifest_payload_sha256": manifest_hash,
        "challenge_sha256": commitment["sha256"],
        "collection_design_sha256": design_hash,
        "runtime_policy_sha256": policy_hash,
        "records": records,
        "coverage": coverage,
        "missing_scenarios": sorted(set(expected) - covered),
        "review_rate": sum(row["actual_decision"] == "REVIEW" for row in records) / count,
        "confident_benign_rate": sum(row["actual_decision"] == "BENIGN" for row in records) / count,
        "confident_malicious_rate": sum(row["actual_decision"] == "MALICIOUS" for row in records)
        / count,
        "pair_agreement": sum(pair_results) / len(pair_results) if pair_results else None,
        "pair_agreement_definition": (
            "equal decision distributions across observed scenarios per cohort"
        ),
        "threshold_tuning_allowed": False,
    }
    _atomic_write(report_path, sign_evidence(output))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--design", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    result = evaluate_challenge(
        args.package_dir, args.challenge, args.manifest, args.design, evidence_dir=args.evidence_dir
    )
    print(f"Challenge evaluation: {result['status']}; coverage={result['coverage']}")
    if result["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
