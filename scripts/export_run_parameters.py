from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path
from typing import Any

import yaml

from ml.scenario_collection import RunDraft


def _powershell_literal(value: int | float | str | bool) -> str:
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return str(value)


def _bash_name(name: str) -> str:
    return "DATN_" + re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()


def render_parameters(draft: RunDraft, output_format: str) -> str:
    payload: dict[str, Any] = {
        "run_id": draft.run_id,
        "scenario_id": draft.scenario_id,
        "family": draft.family,
        "label": draft.label,
        "scenario_parameters": draft.scenario_parameters,
    }
    if output_format == "json":
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output_format == "powershell":
        lines = [
            f"$DatnRunId = {_powershell_literal(draft.run_id)}",
            f"$DatnScenarioId = {_powershell_literal(draft.scenario_id)}",
            "$DatnParameters = @{",
        ]
        lines.extend(
            f"  {key} = {_powershell_literal(value)}"
            for key, value in sorted(draft.scenario_parameters.items())
        )
        lines.append("}")
        return "\n".join(lines) + "\n"
    if output_format == "bash":
        values = {
            "run_id": draft.run_id,
            "scenario_id": draft.scenario_id,
            **draft.scenario_parameters,
        }
        return "\n".join(
            f"{_bash_name(key)}={shlex.quote(str(value))}"
            for key, value in sorted(values.items())
        ) + "\n"
    raise ValueError(f"unsupported output format: {output_format}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a run draft and export its frozen execution parameters"
    )
    parser.add_argument("--draft", type=Path, required=True)
    parser.add_argument(
        "--format",
        choices=("json", "powershell", "bash"),
        default="json",
    )
    args = parser.parse_args()

    try:
        draft = RunDraft.model_validate(
            yaml.safe_load(args.draft.read_text(encoding="utf-8"))
        )
        print(render_parameters(draft, args.format), end="")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(json.dumps({"status": "ERROR", "detail": str(exc)}, indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
