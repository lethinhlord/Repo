#!/usr/bin/env python3
"""Attach official PyPI artifact hashes to an already pinned requirements file."""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")


def artifact_hashes(name: str, version: str) -> list[str]:
    encoded_name = urllib.parse.quote(name, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    url = f"https://pypi.org/pypi/{encoded_name}/{encoded_version}/json"
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        document = json.load(response)
    hashes = sorted(
        {
            item["digests"]["sha256"]
            for item in document.get("urls", [])
            if item.get("digests", {}).get("sha256")
        }
    )
    if not hashes:
        raise RuntimeError(f"PyPI returned no SHA-256 artifacts for {name}=={version}")
    return hashes


def lock(input_path: Path, output_path: Path) -> None:
    result: list[str] = []
    for line in input_path.read_text(encoding="utf-8").splitlines():
        match = PIN.fullmatch(line)
        if match is None:
            result.append(line)
            continue
        name, version = match.groups()
        hashes = artifact_hashes(name, version)
        result.append(f"{name}=={version} \\")
        for index, digest in enumerate(hashes):
            suffix = " \\" if index < len(hashes) - 1 else ""
            result.append(f"    --hash=sha256:{digest}{suffix}")
    output_path.write_text("\n".join(result) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    lock(arguments.input, arguments.output)


if __name__ == "__main__":
    main()
