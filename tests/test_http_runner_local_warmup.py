from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_training_http.ps1"


def test_local_file_hold_preserves_one_http_action_per_iteration():
    text = RUNNER.read_text(encoding="utf-8")

    assert "file:///C:/Windows/win.ini" in text
    assert "--rate '1/2s'" in text
    assert text.count("'file:///C:/Windows/win.ini'") == 2
    assert text.index("--write-out '%{http_code}' $url") < text.index("'file:///C:/Windows/win.ini'")

    # One frozen /beacon URL is constructed per loop iteration.
    assert text.count('/beacon?run=$RunNonce') == 1
    assert "for ($index=1; $index -le $Count; $index++)" in text

    # One HTTP success receipt per iteration.
    assert "HTTP_REQUEST_OK seq=$index status=200" in text
    assert "$LASTEXITCODE -ne 0" in text
    assert "'200'" in text


def test_warmup_does_not_replace_frozen_action_schedule():
    text = RUNNER.read_text(encoding="utf-8")

    assert "$scheduled=$previousStart+$gaps[$index-2]" in text
    assert "HTTP missed schedule; abort run" in text
    assert "HTTP_ACTION_COMPLETE count=$Count nonce=$RunNonce" in text
