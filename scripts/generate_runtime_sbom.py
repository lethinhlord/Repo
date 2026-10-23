#!/usr/bin/env python3
"""Generate a deterministic CycloneDX inventory from the hashed runtime lock."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+) \\$")
HASH = re.compile(r"^\s+--hash=sha256:([0-9a-f]{64})(?: \\)?$")


def components(lock_path: Path) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        pinned = PIN.fullmatch(line)
        if pinned is not None:
            name, version = pinned.groups()
            current = {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{version}",
                "hashes": [],
            }
            result.append(current)
            continue
        digest = HASH.fullmatch(line)
        if digest is not None and current is not None:
            hashes = current["hashes"]
            assert isinstance(hashes, list)
            hashes.append({"alg": "SHA-256", "content": digest.group(1)})
    if not result or any(not component["hashes"] for component in result):
        raise ValueError("runtime lock is missing pinned packages or SHA-256 hashes")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--lock", type=Path, default=Path("requirements-runtime.lock")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/sbom/python-runtime.cdx.json")
    )
    arguments = parser.parse_args()
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "datn-ai-soar-api"}},
        "components": components(arguments.lock),
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"SBOM contains {len(document['components'])} pinned components")


if __name__ == "__main__":
    main()
