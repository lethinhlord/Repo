import json
import os
import random
import shutil
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import pytest


def profile():
    return dict(
        profile_version="lab-http-workflow-v2",
        transport="http",
        endpoint="http://10.40.0.10:8081/beacon",
        expected_action_count=4,
        base_intervals_seconds="2,4,2",
        http_methods_csv="GET,GET,POST,POST",
        request_body_bytes_csv="0,0,512,1024",
        response_body_bytes_csv="256,512,128,128",
    )


def test_profile_version_keeps_frozen_seed_and_wire_contract():
    import random

    from ml.execution_profile import freeze_execution_profile, validate_frozen_profile
    from ml.http_workflow import validate_http_transaction

    p = profile()
    v = freeze_execution_profile(p, random.Random(42), {}, "workflow-unit", 42)
    assert v["execution_profile_version"] == "lab-http-workflow-v2"
    validate_frozen_profile(p, v)
    n = v["run_nonce"]
    variant = v["variant_index"]
    event = {
        "http": {
            "url": f"/beacon?run={n}&v={variant}&n=3&z=128",
            "http_method": "POST",
            "status": 200,
            "length": 128,
        }
    }
    validate_http_transaction(event, v, 3)
    event["http"]["http_method"] = "GET"
    with pytest.raises(ValueError):
        validate_http_transaction(event, v, 3)


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_body_bytes_csv", "0,0,-1,1"),
        ("http_methods_csv", "GET,GET,DELETE,POST"),
        ("response_body_bytes_csv", "1,2,3"),
        ("expected_action_count", True),
        ("endpoint", "http://example.com/beacon"),
        ("request_body_bytes_csv", "1,0,2,3"),
    ],
)
def test_invalid_profile_is_rejected_before_actions(field, value):
    from ml.execution_profile import profile_intervals

    p = profile()
    p[field] = value
    with pytest.raises(ValueError):
        profile_intervals(p)


def test_lab_server_exchanges_only_bounded_non_executable_payloads():
    from ml.http_workflow import LabHTTPServer

    server = LabHTTPServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/beacon?run=unitnonce123&v=2&n=1&z=512"
        for body in (None, b"Z" * 1024):
            request = urllib.request.Request(url, data=body)
            with urllib.request.urlopen(request, timeout=3) as response:
                assert response.status == 200 and response.read() == b"Z" * 512
                assert response.headers["Connection"].casefold() == "close"
        # Content-Length lets the client finish before the server's request
        # thread records completion. Await that asynchronous log, not a sleep
        # assumption about native scheduling.
        deadline = time.monotonic() + 2
        while len(server.observations) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        records = server.observations
        assert [r["method"] for r in records] == ["GET", "POST"]
        assert records[-1]["request_bytes"] == 1024
        assert all("body" not in r for r in records)
        assert json.loads(json.dumps(records)) == records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.skipif(os.name != "nt", reason="native Windows curl/PowerShell actor")
def test_native_workflow_sends_frozen_methods_payloads_and_closes_connections(tmp_path):
    from ml.execution_profile import freeze_execution_profile
    from ml.http_workflow import LabHTTPServer

    server = LabHTTPServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        root = Path(__file__).resolve().parents[1]
        original = (root / "scripts/run_supplemental_http.ps1").read_text()
        endpoint = f"http://127.0.0.1:{server.server_port}/beacon"
        # Substitute only the unreachable isolated-lab route for loopback. The
        # actual actor, native curl and byte/argument handling run unchanged.
        runner = tmp_path / "runner with spaces.ps1"
        runner.write_text(original.replace("http://10.40.0.10:8081/beacon", endpoint))
        value = freeze_execution_profile(profile(), random.Random(42), {}, "native-workflow", 42)
        value["endpoint"] = endpoint
        parameters = tmp_path / "frozen parameters.json"
        parameters.write_text(json.dumps(value))
        result = subprocess.run(
            [
                shutil.which("powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(runner),
                "-ParametersPath",
                str(parameters),
            ],
            capture_output=True,
            text=True,
            timeout=45,
        )
        assert result.returncode == 0, result.stderr
        assert "HTTP_ACTION_COMPLETE count=4" in result.stdout
        assert [r["method"] for r in server.observations] == ["GET", "GET", "POST", "POST"]
        assert [r["request_bytes"] for r in server.observations] == [0, 0, 512, 1024]
        assert [r["response_bytes"] for r in server.observations] == [256, 512, 128, 128]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
