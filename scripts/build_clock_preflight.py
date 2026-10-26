from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

import yaml

from ml.scenario_collection import ClockPreflight


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and write immutable cross-VM clock evidence"
    )
    parser.add_argument("--controller", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--wazuh", required=True)
    parser.add_argument("--sensor", required=True)
    parser.add_argument("--attacker", required=True)
    parser.add_argument("--maximum-skew-seconds", type=float, default=5.0)
    parser.add_argument("--maximum-capture-age-seconds", type=float, default=120.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite clock evidence: {args.output}")
    document = ClockPreflight(
        captured_at=datetime.now(UTC),
        controller_utc=args.controller,
        target_utc=args.target,
        wazuh_utc=args.wazuh,
        sensor_utc=args.sensor,
        attacker_utc=args.attacker,
        maximum_skew_seconds=args.maximum_skew_seconds,
        maximum_capture_age_seconds=args.maximum_capture_age_seconds,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(document.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    print(f"CLOCK_PREFLIGHT=PASS path={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
