from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from ml.scenario_collection import RunDraft


def _powershell_literal(value: int | float | str | bool) -> str:
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return str(value)


def _bash_name(name: str) -> str:
    return "DATN_" + re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()


def _sha256_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_frozen_parameters(project_root: Path, run_id: str) -> tuple[dict[str, Any], str]:
    evidence_dir = project_root.resolve() / "evidence/scenario-runs" / run_id
    state = json.loads(
        (evidence_dir / ".collection_state.json").read_text(encoding="utf-8")
    )
    payload = json.loads(
        (evidence_dir / "execution-parameters.json").read_text(encoding="utf-8")
    )
    digest = _sha256_payload(payload)
    if state.get("status") != "STARTED":
        raise ValueError("parameters may be exported only for a STARTED run")
    if state.get("execution_receipt") is not None:
        raise ValueError("parameters must be exported before the action begins")
    if payload.get("run_id") != run_id or digest != state.get(
        "frozen_parameters_sha256"
    ):
        raise ValueError("frozen execution parameters are inconsistent")
    return payload, digest


def render_parameters(
    draft_or_payload: RunDraft | dict[str, Any],
    output_format: str,
    *,
    digest: str | None = None,
) -> str:
    if isinstance(draft_or_payload, RunDraft):
        draft = draft_or_payload
        payload: dict[str, Any] = {
            "run_id": draft.run_id,
            "scenario_id": draft.scenario_id,
            "family": draft.family,
            "label": draft.label,
            "scenario_parameters": draft.scenario_parameters,
        }
    else:
        payload = draft_or_payload
    digest = digest or _sha256_payload(payload)
    if output_format == "json":
        return json.dumps(
            {**payload, "frozen_parameters_sha256": digest},
            indent=2,
            sort_keys=True,
        ) + "\n"
    if output_format == "powershell":
        lines = [
            f"$DatnRunId = {_powershell_literal(payload['run_id'])}",
            f"$DatnScenarioId = {_powershell_literal(payload['scenario_id'])}",
            f"$DatnParametersSha256 = {_powershell_literal(digest)}",
            "$DatnParameters = @{",
        ]
        lines.extend(
            f"  {key} = {_powershell_literal(value)}"
            for key, value in sorted(payload["scenario_parameters"].items())
        )
        lines.append("}")
        return "\n".join(lines) + "\n"
    if output_format == "bash":
        values = {
            "run_id": payload["run_id"],
            "scenario_id": payload["scenario_id"],
            "parameters_sha256": digest,
            **payload["scenario_parameters"],
        }
        return "\n".join(
            f"{_bash_name(key)}={shlex.quote(str(value))}"
            for key, value in sorted(values.items())
        ) + "\n"
    raise ValueError(f"unsupported output format: {output_format}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export the collector-frozen parameters of a STARTED run"
    )
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--format",
        choices=("json", "powershell", "bash"),
        default="json",
    )
    args = parser.parse_args()

    try:
        payload, digest = load_frozen_parameters(args.project_root, args.run_id)
        print(render_parameters(payload, args.format, digest=digest), end="")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
