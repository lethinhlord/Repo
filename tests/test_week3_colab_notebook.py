import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "week3_train_colab.ipynb"


def _notebook() -> dict:
    return json.loads(NOTEBOOK.read_text(encoding="utf-8"))


def _source_text() -> str:
    notebook = _notebook()
    return "\n".join(
        "".join(cell.get("source", [])) for cell in notebook.get("cells", [])
    )


def test_colab_notebook_is_valid_and_discoverable() -> None:
    notebook = _notebook()

    assert notebook["nbformat"] == 4
    assert notebook["metadata"]["kernelspec"]["language"] == "python"
    assert notebook["metadata"]["colab"]["name"] == "week3_train_colab.ipynb"
    assert any(cell["cell_type"] == "markdown" for cell in notebook["cells"])
    assert any(cell["cell_type"] == "code" for cell in notebook["cells"])


def test_colab_notebook_orchestrates_the_trusted_pipeline() -> None:
    source = _source_text()

    required_steps = (
        "git clone --branch",
        "requirements-ml.lock",
        "requirements-notebook.lock",
        "drive.mount",
        "dataset_manifest.json",
        "python -m ruff check .",
        "python -m pytest -q",
        "python -m ml.train --config ml/training_config.yaml",
        "metrics_validation.json",
        "leakage_audit.json",
        "model-package-week3.tar.gz",
    )
    assert all(step in source for step in required_steps)


def test_colab_notebook_preserves_the_locked_test_boundary() -> None:
    source = _source_text()

    assert "locked_test_status" in source
    assert "UNOPENED" in source
    assert "LOCKED_TEST_PATH.exists()" in source
    assert "python -m ml.evaluate" not in source
    assert "python -m ml.freeze_model" not in source
