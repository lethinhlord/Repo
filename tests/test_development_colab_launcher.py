"""Colab host configuration must not leak its inline backend into the trainer."""

import ast
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "docs/colab/development_48runs_colab.ipynb"
APPROVED_SOURCE = "0fcacb145146eb9657739e76b56a870f75818ac1"


def notebook(path):
    return json.loads(path.read_bytes())


def text(book, index):
    return "".join(book["cells"][index]["source"])


def test_launcher_subprocess_environment_overrides_colab_backend_only_in_child(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("MPLBACKEND", "module://matplotlib_inline.backend_inline")
    monkeypatch.setenv("PYTHONPATH", "colab-kernel-only")
    tree = ast.parse(text(notebook(LAUNCHER), 6))
    setup = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "train_env"
                for target in node.targets)
        or isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == "train_env"
        and node.value.func.attr == "pop"
    ]
    context = dict(os=os, TRAIN_ENV=tmp_path / "venv", TRAIN_PYTHON=tmp_path / "venv/bin/python")
    exec(compile(ast.Module(body=setup, type_ignores=[]), "<launcher-env>", "exec"), context)
    child = context["train_env"]
    assert child["MPLBACKEND"] == "Agg"
    assert "PYTHONPATH" not in child
    assert child["PYTHONNOUSERSITE"] == "1"
    assert os.environ["MPLBACKEND"] == "module://matplotlib_inline.backend_inline"
    assert os.environ["PYTHONPATH"] == "colab-kernel-only"


def test_launcher_preserves_all_approved_workflow_code_except_host_configuration():
    original = notebook(ROOT / "notebooks/development_train_colab.ipynb")
    corrected = notebook(LAUNCHER)
    assert len(corrected["cells"]) == len(original["cells"])
    for index, (old, new) in enumerate(zip(original["cells"], corrected["cells"], strict=True)):
        assert old["cell_type"] == new["cell_type"]
        if old["cell_type"] != "code":
            continue
        expected = text(original, index)
        if index == 2:
            expected = expected.replace(
                'EXPECTED_TRAINING_COMMIT = ""',
                f'EXPECTED_TRAINING_COMMIT = "{APPROVED_SOURCE}"',
            )
        elif index == 6:
            expected = expected.replace(
                '    "PYTHONNOUSERSITE": "1",\n',
                '    "PYTHONNOUSERSITE": "1",\n    "MPLBACKEND": "Agg",\n',
            )
        assert text(corrected, index) == expected
        ast.parse(text(corrected, index))
    preflight = ast.parse(text(corrected, 12)).body[0].value.value
    ast.parse(preflight)


def test_launcher_pins_the_approved_training_source_and_existing_drive_layout():
    context = {}
    exec(text(notebook(LAUNCHER), 2), context)
    assert context["EXPECTED_TRAINING_COMMIT"] == APPROVED_SOURCE
    assert context["BRANCH"] == "main"
    assert context["DRIVE_DATA_DIR"].as_posix().endswith(
        "MyDrive/DATN/development-3day-data/processed-development-v1"
    )
    assert context["EXPECTED_FILES"] == (
        "train.jsonl", "dataset_manifest.json", "colab-upload.sha256"
    )
