"""Exercise the real shell entry point with recording CLI doubles; no lab traffic."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("mode", ["default", "active", "explicit"])
@pytest.mark.parametrize("target", ["0", "1"])
def test_verifier_forwards_one_active_source_to_final_audit(tmp_path, mode, target):
    shell = shutil.which("sh")
    if os.name == "nt":
        shell = "C:/Program Files/Git/bin/sh.exe"
    if not shell or not Path(shell).is_file():
        pytest.skip("POSIX shell unavailable")
    script = tmp_path / "scripts/verify_collection_dataset.sh"
    script.parent.mkdir()
    shutil.copyfile(ROOT / "scripts/verify_collection_dataset.sh", script)
    for rel in ("config/collection-sources.yaml", "operator-logs/collection-sources-active.yaml",
                "operator-logs/explicit active.yaml"):
        p = tmp_path / rel
        p.parent.mkdir(exist_ok=True)
        p.write_text("{}\n", encoding="utf-8")
    if mode == "default":
        (tmp_path / "operator-logs/collection-sources-active.yaml").unlink()
    stub = tmp_path / "record-command"
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> trace.txt\n',
                    encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    env = {**os.environ, "PYTHON": "./record-command", "RUFF": "./record-command",
           "REQUIRE_TARGET": target}
    env.pop("COLLECTION_SOURCE_CONFIG", None)
    if mode == "explicit":
        env["COLLECTION_SOURCE_CONFIG"] = "operator-logs/explicit active.yaml"
    result = subprocess.run([shell, str(script)], cwd=tmp_path, env=env,
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    args = (tmp_path / "trace.txt").read_text().splitlines()
    expected = {"default": "config/collection-sources.yaml",
                "active": "operator-logs/collection-sources-active.yaml",
                "explicit": "operator-logs/explicit active.yaml"}[mode]
    assert args.count("--source-config") == 1
    assert args[args.index("--source-config") + 1] == expected
    assert ("--require-target" in args) == (target == "1")
