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
        "colab-upload.sha256",
        "hashlib.sha256",
        'manifest.get("group_key") in {"scenario_id", "cohort_id"}',
        'train_cohorts & validation_cohorts',
        'row.get("purpose", "trainable") == "trainable"',
        'manifest.get("feature_schema_version") == "features-v3"',
        'manifest.get("collection_audit", {}).get("status")',
        'row["scenario_id"]',
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
    code = "\n".join(
        "".join(c.get("source", [])) for c in _notebook()["cells"] if c["cell_type"] == "code"
    )
    assert "python -m ml.freeze_model" not in code


def test_handoff_distinguishes_smoke_from_real_package_acceptance() -> None:
    source = _source_text()
    for step in ('tarfile.open', 'model-package-week3.tar.gz', 'builder_git_commit',
                 'ml.freeze_model', '--verify-only', '/model/ready', 'smoke PASS'):
        assert step in source


def test_handoff_is_one_fail_stop_block_with_fresh_staging_and_identity_checks() -> None:
    import re
    source = _source_text()
    block = next(b for b in re.findall(r'```bash\n(.*?)```', source, re.S)
                 if 'ml.freeze_model' in b)
    assert 'set -eu' in block and 'mktemp -d' in block
    assert block.index('mkdir "$MODEL_PACKAGE_DIR"') < block.index('ml.freeze_model')
    assert block.count('--package-dir "$MODEL_PACKAGE_DIR"') == 2
    assert 'dataset_manifest_payload_sha256' in block
    assert 'EXPECTED_MODEL_VERSION' in block and 'EXPECTED_ARCHIVE_SHA256' in block
    assert 'test ! -e ml/model-package && cp' not in block


def test_handoff_uses_new_versioned_release_and_safe_archive_members() -> None:
    source = _source_text()
    assert 'artifacts/runtime/model-releases/' in source
    assert 'MODEL_PACKAGE_HOST_DIR' in source
    assert 'tar -xzf' not in source
    assert 'member.issym()' in source and 'member.islnk()' in source
    assert '/app/ml/model-package' in source
