import hashlib
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest
from test_ml_package import create_package

from ml.freeze_model import freeze

ROOT = Path(__file__).resolve().parents[1]


def test_verifier_cli_accepts_signed_active_package(tmp_path, monkeypatch):
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", "synthetic-test-signing-key-at-least-32-bytes")
    package = tmp_path / "SYNTHETIC-NOT-LAB"
    create_package(package)
    freeze(package)
    result = subprocess.run(
        [sys.executable, "-m", "scripts.verify_model_package", "--package-dir", str(package)],
        cwd=ROOT, env=os.environ.copy(), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS:" in result.stdout


def test_notebook_preinstall_source_binding():
    notebook = json.loads((ROOT / "notebooks/week3_train_colab.ipynb").read_text(encoding="utf-8"))
    code = "\n".join("".join(c["source"]) for c in notebook["cells"] if c["cell_type"] == "code")
    before_install = code.split("%pip")[0]
    assert "EXPECTED_TRAINING_COMMIT" in before_install
    assert 'builder_git_commit' in before_install
    assert 'builder_config_sha256' in before_install
    assert 'checkout", "--detach"' in before_install
    assert 'PROJECT_DIR.exists()' in before_install
    assert 'feature/week3-model-training' not in code


def test_notebook_gate_rejects_unapproved_or_mismatched_source(tmp_path, monkeypatch):
    import hashlib
    import types

    import pytest

    google = types.ModuleType("google")
    colab = types.ModuleType("google.colab")
    colab.drive = types.SimpleNamespace(mount=lambda _: None)
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.colab", colab)
    notebook = json.loads((ROOT / "notebooks/week3_train_colab.ipynb").read_text("utf-8"))
    gate = "".join(notebook["cells"][4]["source"])
    stage = tmp_path / "staging"
    stage.mkdir()
    names = ("train.jsonl", "validation.jsonl", "dataset_manifest.json")
    (stage / names[0]).write_text("synthetic-train")
    (stage / names[1]).write_text("synthetic-validation")
    (stage / names[2]).write_text(json.dumps({
        "locked_test_status": "UNOPENED",
        "provenance": {"builder_git_commit": "a" * 40},
    }))
    (stage / "colab-upload.sha256").write_text("".join(
        f"{hashlib.sha256((stage / name).read_bytes()).hexdigest()}  {name}\n"
        for name in names
    ))
    namespace = {
        "DRIVE_DATA_DIR": stage, "PROJECT_DIR": tmp_path / "fresh-project",
        "EXPECTED_TRAINING_COMMIT": "", "EXPECTED_FILES": (*names, "colab-upload.sha256"),
        "EXPECTED_DATA_FILES": names, "CHECKSUM_FILE": "colab-upload.sha256",
    }
    with pytest.raises(RuntimeError, match="owner-approved"):
        exec(gate, namespace)
    namespace["EXPECTED_TRAINING_COMMIT"] = "b" * 40
    with pytest.raises(RuntimeError, match="differs from manifest"):
        exec(gate, namespace)
    namespace["EXPECTED_TRAINING_COMMIT"] = "a" * 40
    namespace["PROJECT_DIR"].mkdir()
    with pytest.raises(RuntimeError, match="Existing project refused"):
        exec(gate, namespace)


@pytest.mark.parametrize("fault", [None, "checksum", "config"])
def test_notebook_checks_real_detached_checkout_before_install(tmp_path, monkeypatch, fault):
    """Run the exact notebook cell against local Git, without Drive or pip."""
    source = tmp_path / "trusted-source"
    source.mkdir()
    (source / "ml").mkdir()
    (source / ".gitattributes").write_bytes((ROOT / ".gitattributes").read_bytes())
    config = b"synthetic-config: true\n"
    (source / "ml/training_config.yaml").write_bytes(config)
    commands = [
        ["git", "init", "-b", "main"], ["git", "add", "."],
        ["git", "-c", "user.name=Synthetic QA", "-c", "user.email=qa@example.invalid",
         "commit", "-m", "Synthetic source, not lab evidence"],
    ]
    for command in commands:
        subprocess.run(command, cwd=source, check=True, capture_output=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    staging = tmp_path / "staging"
    staging.mkdir()
    names = ("train.jsonl", "validation.jsonl", "dataset_manifest.json")
    (staging / names[0]).write_text("SYNTHETIC-NOT-LAB\n")
    (staging / names[1]).write_text("SYNTHETIC-NOT-LAB\n")
    manifest = {"locked_test_status": "UNOPENED", "provenance": {
        "builder_git_commit": sha,
        "builder_config_sha256": hashlib.sha256(config).hexdigest() if fault != "config"
        else "0" * 64,
    }}
    (staging / names[2]).write_text(json.dumps(manifest))
    (staging / "colab-upload.sha256").write_text("".join(
        f"{hashlib.sha256((staging / name).read_bytes()).hexdigest()}  {name}\n"
        for name in names
    ))
    if fault == "checksum":
        (staging / names[0]).write_text("changed-after-checksum")
    google = types.ModuleType("google")
    colab = types.ModuleType("google.colab")
    colab.drive = types.SimpleNamespace(mount=lambda _: None)
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.colab", colab)
    monkeypatch.chdir(tmp_path)
    namespace = {"DRIVE_DATA_DIR": staging, "PROJECT_DIR": tmp_path / "checkout",
                 "EXPECTED_TRAINING_COMMIT": sha, "BRANCH": "main", "REPO_URL": str(source),
                 "EXPECTED_FILES": (*names, "colab-upload.sha256"),
                 "EXPECTED_DATA_FILES": names, "CHECKSUM_FILE": "colab-upload.sha256"}
    notebook = json.loads((ROOT / "notebooks/week3_train_colab.ipynb").read_text("utf-8"))
    gate = "".join(notebook["cells"][4]["source"])
    if fault:
        with pytest.raises(RuntimeError, match="SHA-256 mismatch|Training config differs"):
            exec(gate, namespace)
    else:
        exec(gate, namespace)
        assert namespace["commit"] == sha
        assert subprocess.run(["git", "symbolic-ref", "-q", "HEAD"],
                              cwd=namespace["PROJECT_DIR"], capture_output=True).returncode != 0
