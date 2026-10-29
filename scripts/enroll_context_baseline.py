"""Build a separate history snapshot from a reviewed baseline-only Wazuh capture."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ml.context import build_baseline, with_dns_suffix_history


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/context-baseline.json"))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--ttl-hours", type=float, default=24.0)
    parser.add_argument("--windows-agent", default="WIN11-TARGET")
    parser.add_argument("--dns-suffix", action="append", default=[],
                        help="pre-run inventory suffix; requires observed enrollment DNS evidence")
    parser.add_argument("--approved-enrollment", action="store_true", required=True,
                        help="confirm this separate capture contains reviewed baseline activity")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("baseline output already exists; create a new revision, never overwrite")
    if not 0 < args.ttl_hours <= 168:
        parser.error("ttl-hours must be in (0,168]")
    try:
        raw = args.capture.read_bytes()
        rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
        if not all(isinstance(row, dict) for row in rows):
            raise ValueError("capture must contain JSON objects")
        digest = hashlib.sha256(raw).hexdigest()
        now = datetime.now(UTC)
        snapshot = build_baseline(
            rows, revision=args.revision, captured_at=now,
            valid_until=now + timedelta(hours=args.ttl_hours),
            source_capture_sha256=digest, windows_agent_name=args.windows_agent,
        )
        if args.dns_suffix:
            snapshot = with_dns_suffix_history(snapshot, args.dns_suffix)
        capture_path = args.output.parent / "context-captures" / f"{digest}.jsonl"
        capture_path.parent.mkdir(parents=True, exist_ok=True)
        if (
            capture_path.exists()
            and hashlib.sha256(capture_path.read_bytes()).hexdigest() != digest
        ):
            raise ValueError("existing context capture does not match its digest")
        if not capture_path.exists():
            # Publish the bytes already validated and hashed, never re-read the live input.
            with tempfile.NamedTemporaryFile(dir=capture_path.parent, delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                with suppress(FileExistsError):
                    os.link(temporary, capture_path)
            finally:
                temporary.unlink()
        if hashlib.sha256(capture_path.read_bytes()).hexdigest() != digest:
            raise ValueError("published enrollment capture does not match the validated bytes")
        # Exclusive output creation prevents concurrent operators replacing a snapshot.
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(snapshot.model_dump_json(indent=2) + "\n")
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}))
        return 1
    print(json.dumps({"status": "ENROLLED", "revision": snapshot.revision,
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      "source_capture_sha256": digest,
                      "valid_until": snapshot.valid_until.isoformat()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
