"""Recompute the preflight channel report from raw canary evidence."""

import argparse
import json
from pathlib import Path

from ml.preflight import verify_preflight_capture


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--canary-id", required=True)
    parser.add_argument("--since", required=True)
    args = parser.parse_args()
    try:
        report = verify_preflight_capture(args.capture, args.canary_id, args.since)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
