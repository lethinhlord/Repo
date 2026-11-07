"""Exercise legacy milestone scripts against isolated CLI doubles, never a live stack."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_week1_compose_has_an_explicit_model_free_mock_boundary():
    compose = yaml.safe_load((ROOT / "compose.week1.yaml").read_text())
    api = compose["services"]["api"]
    assert api["image"] == "datn-ai-soar-api:week1"
    assert api["environment"]["MODEL_PACKAGE_DIR"] == ""
    assert api["environment"]["ALLOW_MOCK_INFERENCE"] == "true"
    assert api["environment"]["VT_MODE"] == "mock"
    assert api["environment"]["NOTIFICATION_MODE"] == "log"
    assert "volumes" not in api
    assert "/health" in " ".join(api["healthcheck"]["test"])
    n8n = compose["services"]["n8n"]
    assert n8n["ports"] == ["127.0.0.1:5678:5678"]
    assert n8n["environment"]["N8N_ENCRYPTION_KEY"].startswith("${N8N_ENCRYPTION_KEY:?")
    trained_compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert n8n["image"] == trained_compose["services"]["n8n"]["image"]


def test_fresh_week1_bootstrap_and_repeat_preserve_secrets_and_use_matching_qa_image(tmp_path):
    shell = shutil.which("sh")
    if shell is None and Path("C:/Program Files/Git/bin/bash.exe").exists():
        shell = "C:/Program Files/Git/bin/bash.exe"
    if shell is None:
        pytest.skip("POSIX shell is not available")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "bin").mkdir()
    for name in ("deploy_week1.sh", "verify_week1.sh"):
        shutil.copyfile(ROOT / "scripts" / name, tmp_path / "scripts" / name)
    for name, body in {
        "bin/docker": '#!/bin/sh\nprintf "%s\\n" "$*" >> cli.log\ncat >/dev/null\n',
        "bin/curl": '#!/bin/sh\nprintf "{}"\n',
        "bin/openssl": '#!/bin/sh\nprintf "isolated-test-secret-01234567890123456789"\n',
        "scripts/build_reproducible_image.sh": '#!/bin/sh\nprintf "build %s\\n" "$*" >> cli.log\n',
    }.items():
        file = tmp_path / name
        file.write_text(body, encoding="utf-8", newline="\n")
        file.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = str(tmp_path / "bin") + os.pathsep + environment["PATH"]
    # Prevent Git Bash from translating CLI mount arguments in these doubles.
    environment["MSYS_NO_PATHCONV"] = "1"
    previous = None
    for _ in range(2):
        result = subprocess.run([shell, "-c", 'PATH="$PWD/bin:$PATH"; export PATH; '
                                 'exec sh scripts/deploy_week1.sh'], cwd=tmp_path,
                                env=environment, input="", capture_output=True,
                                text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        content = (tmp_path / ".env.week1").read_text()
        for key in ("N8N_ENCRYPTION_KEY", "WAZUH_WEBHOOK_SECRET", "MODEL_PACKAGE_SIGNING_KEY"):
            assert content.count(key + "=") == 1
            assert "isolated-test-secret" in content
        if previous is not None:
            assert content == previous
        previous = content
    verification = subprocess.run([shell, "-c", 'PATH="$PWD/bin:$PATH"; export PATH; '
                                   'exec sh scripts/verify_week1.sh'], cwd=tmp_path,
                                  env=environment, input="", capture_output=True,
                                  text=True, timeout=20)
    assert verification.returncode == 0, verification.stderr
    commands = (tmp_path / "cli.log").read_text()
    assert "build datn-ai-soar-api:week1" in commands
    assert "datn-ai-soar-api:week1-qa python -m pytest" in commands
    assert "datn-ai-soar-api:week1-qa python -m ruff" in commands
    assert "--build-arg API_IMAGE=datn-ai-soar-api:week1" in commands
    assert "-f compose.week1.yaml --env-file .env.week1" in commands
    assert "compose down" not in commands
