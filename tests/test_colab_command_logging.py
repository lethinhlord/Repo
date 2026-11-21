"""Notebook process logging and isolated dependency contract."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_logging_streams_before_child_exit_and_preserves_failures(tmp_path, monkeypatch):
    from ml.command_logging import run_logged

    log = tmp_path / "phases.log"
    gate = tmp_path / "release"
    output = []

    def displayed(message):
        output.append(message)
        if message.rstrip() == "ready-signal":
            assert "ready-signal" in log.read_text(encoding="utf-8")
            gate.touch()

    monkeypatch.setattr("ml.command_logging.display_line", displayed)
    child = (
        "import pathlib, sys, time\n"
        "print('ready-signal', flush=True)\n"
        "gate = pathlib.Path(sys.argv[1])\n"
        "for _ in range(100):\n"
        "    if gate.exists(): break\n"
        "    time.sleep(.02)\n"
        "print('diagnostic', file=sys.stderr)\n"
        "sys.exit(7 if gate.exists() else 8)\n"
    )
    with pytest.raises(subprocess.CalledProcessError) as error:
        run_logged("quality", [sys.executable, "-u", "-c", child, str(gate)], log)
    assert error.value.returncode == 7
    run_logged("next", [sys.executable, "-c", "print('second')"], log)
    combined = log.read_text(encoding="utf-8")
    assert all(text in combined for text in ("quality", "diagnostic", "7", "next", "second"))
    assert any("diagnostic" in line for line in output)


@pytest.mark.skipif(os.name != "posix", reason="Colab uses POSIX process groups")
def test_logging_interrupt_terminates_descendant_and_reaps_child(tmp_path, monkeypatch):
    from ml.command_logging import run_logged

    marker = tmp_path / "orphan-ran"
    grandchild = (
        "import pathlib, sys, time; time.sleep(1); pathlib.Path(sys.argv[1]).touch()"
    )
    child = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
        "print('child ready', flush=True); time.sleep(60)"
    )

    def interrupt(message):
        if message.rstrip() == "child ready":
            raise KeyboardInterrupt

    monkeypatch.setattr("ml.command_logging.display_line", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_logged("train", [sys.executable, "-u", "-c", child, grandchild, str(marker)],
                   tmp_path / "interrupted.log")
    time.sleep(1.1)
    assert not marker.exists()


def test_notebook_uses_runtime_lock_and_the_same_interpreter_for_quality_and_fit():
    notebook = json.loads((ROOT / "notebooks/week3_train_colab.ipynb").read_bytes())
    code = "\n".join("".join(cell["source"]) for cell in notebook["cells"]
                     if cell["cell_type"] == "code")
    assert "--require-hashes" in code and "requirements-runtime.lock" in code
    assert "TRAIN_PYTHON" in code and "%pip install" not in code
    for module in ("pytest", "ruff", "ml.train"):
        assert f'TRAIN_PYTHON, "-u", "-m", "{module}"' in code
    assert "capture_output=True" not in code


def _cell(marker):
    notebook = json.loads((ROOT / "notebooks/week3_train_colab.ipynb").read_bytes())
    return next(source for c in notebook["cells"] if c["cell_type"] == "code"
                and marker in (source := "".join(c["source"])))


def test_missing_command_records_launch_failure(tmp_path):
    from ml.command_logging import run_logged

    log = tmp_path / "failure.log"
    with pytest.raises(FileNotFoundError):
        run_logged("launch missing", [tmp_path / "missing-executable"], log)
    assert "FileNotFoundError" in log.read_text(encoding="utf-8")


def test_failed_quality_gate_prevents_training_and_all_checks_use_isolated_python(tmp_path):
    import shutil

    commands = []

    def run(phase, command, log, *, env=None):
        commands.append((phase, command))
        if phase == "Full pytest suite":
            raise subprocess.CalledProcessError(1, command)

    env = {
        "TRAIN_PYTHON": tmp_path / "isolated/python", "SESSION_LOG": tmp_path / "train.log",
        "shutil": shutil, "run_logged": run, "train_env": {}, "quality_passed": True,
    }
    with pytest.raises(subprocess.CalledProcessError):
        exec(_cell("quality_passed = False\nif shutil.which"), env)
    assert env["quality_passed"] is False
    with pytest.raises(RuntimeError, match="quality gate"):
        exec(_cell('run_logged("Train and assess models"'), env)
    assert all(command[0] == env["TRAIN_PYTHON"]
               for phase, command in commands if phase in {"Ruff", "Full pytest suite"})
    assert not any("ml.train" in command for _, command in commands)
