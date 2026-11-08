"""Attest that QA tests the deployed runtime's source and pinned distributions."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import subprocess
from pathlib import Path
from typing import Any


def source_inventory(root: Path) -> dict[str, str]:
    inventory = {}
    for folder in ("api", "ml", "config"):
        for path in sorted((root / folder).rglob("*")):
            relative = path.relative_to(root)
            if any(
                part in {
                    "__pycache__", ".model-evaluation-registry", ".model-evaluation-evidence",
                } for part in relative.parts
            ):
                continue
            if relative.parts[:2] == ("ml", "model-package") or path.suffix in {".pyc", ".pyo"}:
                continue
            if relative.parts[:2] == ("ml", "splits") and path.suffix == ".txt":
                continue
            if path.is_symlink():
                raise ValueError(f"unsupported source link: {relative}")
            if path.is_file():
                inventory[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not inventory:
        raise ValueError("runtime source inventory is empty")
    return inventory


def package_inventory() -> dict[str, str]:
    return {
        re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower(): distribution.version
        for distribution in importlib.metadata.distributions()
    }


def verify_snapshots(
    expected_sources: dict[str, str], runtime: dict[str, Any], qa: dict[str, Any],
) -> None:
    if not expected_sources or runtime["sources"] != expected_sources:
        raise ValueError("runtime image source differs from the tested checkout")
    if qa["sources"] != runtime["sources"]:
        raise ValueError("QA image source differs from the runtime image")
    for name, version in runtime["packages"].items():
        if qa["packages"].get(name) != version:
            raise ValueError(f"QA changed runtime distribution: {name}")


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True, encoding="utf-8").strip()


def image_snapshot(image: str) -> dict[str, Any]:
    import inspect

    # Inspect /app without mounting the checkout over the image. Standard library
    # only: never import or execute source from the candidate being attested.
    code = (
        "import hashlib,json,re,importlib.metadata\nfrom pathlib import Path\n"
        + inspect.getsource(source_inventory) + "\n" + inspect.getsource(package_inventory)
        + "\nprint(json.dumps({'sources':source_inventory(Path('/app')),"
        "'packages':package_inventory()}))"
    )
    return json.loads(docker("run", "--rm", "--network", "none", "--entrypoint",
                             "python", image, "-B", "-c", code))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--qa-image", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    runtime_id = docker("image", "inspect", "--format", "{{.Id}}", args.runtime_image)
    running_id = docker("inspect", "--format", "{{.Image}}", args.container)
    if not runtime_id or runtime_id != running_id:
        raise SystemExit("Deployed API container differs from the selected runtime image")
    runtime = image_snapshot(args.runtime_image)
    qa = image_snapshot(args.qa_image)
    verify_snapshots(source_inventory(args.source_root), runtime, qa)
    if runtime_id != docker("image", "inspect", "--format", "{{.Id}}", args.runtime_image):
        raise SystemExit("Runtime image tag changed during verification")
    print(json.dumps({
        "status": "RUNTIME_ARTIFACT_MATCH", "runtime_image_id": runtime_id,
        "source_files": len(runtime["sources"]), "runtime_distributions": len(runtime["packages"]),
        "qa_additional_distributions": sorted(set(qa["packages"]) - set(runtime["packages"])),
    }, indent=2))


if __name__ == "__main__":
    main()
