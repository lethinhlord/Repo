from datetime import timedelta

import pytest
import test_official_collection_acceptance as official

from ml.context import BaselineSnapshot
from scripts.prepare_collection_source import require_fresh_baseline


def test_preparation_requires_fresh_real_context_and_capture(tmp_path, monkeypatch):
    official.prepare_official(tmp_path, monkeypatch)
    path = tmp_path / "evidence/context-baseline.json"
    baseline = BaselineSnapshot.model_validate_json(path.read_bytes())
    require_fresh_baseline(
        tmp_path, path, "WIN11-TARGET", now=baseline.captured_at + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="expired or future"):
        require_fresh_baseline(tmp_path, path, "WIN11-TARGET", now=baseline.valid_until)
    with pytest.raises(ValueError, match="expired or future"):
        require_fresh_baseline(
            tmp_path, path, "WIN11-TARGET", now=baseline.captured_at - timedelta(seconds=1),
        )
    capture = path.parent / "context-captures" / (baseline.source_capture_sha256 + ".jsonl")
    capture.write_text("{}\n")
    with pytest.raises(ValueError):
        require_fresh_baseline(
            tmp_path, path, "WIN11-TARGET", now=baseline.captured_at + timedelta(seconds=1),
        )


@pytest.mark.parametrize("command", ["accept", "authorize"])
def test_g7_cli_checks_fresh_enrollment_before_issuing_or_authorizing(
    tmp_path, monkeypatch, command, capsys,
):
    import sys

    from scripts import collection_release as cli

    calls = []

    def reject(*args):
        calls.append(args)
        raise ValueError("fresh enrollment required")

    monkeypatch.setattr(cli, "_active_source", reject)
    argv = ["collection_release", command, "--source-config", "active.yaml"]
    if command == "accept":
        argv += ["--tag", "unit", "--pilot", "UNIT-PILOT", "--backup-dir", str(tmp_path),
                 "--preflight-dir", str(tmp_path), "--output", str(tmp_path / "no.json")]
    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 1
    assert len(calls) == 1
    assert "fresh enrollment required" in capsys.readouterr().out
    assert not (tmp_path / "no.json").exists()
