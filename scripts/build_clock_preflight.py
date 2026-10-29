from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from ml.clock_evidence import ClockPreflight


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and write immutable cross-VM clock evidence"
    )
    parser.add_argument("--measurements", type=Path)
    for host in ("controller", "target", "wazuh", "sensor", "attacker"):
        parser.add_argument(f"--{host}")
    parser.add_argument("--maximum-skew-seconds", type=float, default=5.0)
    parser.add_argument("--maximum-capture-age-seconds", type=float, default=120.0)
    parser.add_argument("--maximum-roundtrip-seconds", type=float, default=4.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite clock evidence: {args.output}")
    hosts = ("controller", "target", "wazuh", "sensor", "attacker")
    raw = {f"{host}_utc": getattr(args, host) for host in hosts}
    if args.measurements:
        if any(raw.values()):
            parser.error("--measurements cannot be combined with legacy timestamps")
        try:
            raw = {"measurements": json.loads(args.measurements.read_text(encoding="utf-8"))}
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            parser.exit(2, f"clock evidence input error: {exc}\n")
    elif not all(raw.values()):
        parser.error("provide --measurements or all five legacy timestamps")
    try:
        document = ClockPreflight(
            captured_at=datetime.now(UTC),
            maximum_skew_seconds=args.maximum_skew_seconds,
            maximum_capture_age_seconds=args.maximum_capture_age_seconds,
            maximum_roundtrip_seconds=args.maximum_roundtrip_seconds,
            **raw,
        )
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"]) or "clock evidence"
        parser.exit(2, f"clock evidence validation error ({location}): {first['msg']}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(document.model_dump(mode="json", exclude_none=True), sort_keys=False),
        encoding="utf-8",
    )
    print(f"CLOCK_PREFLIGHT=PASS path={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
