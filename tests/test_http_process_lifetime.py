"""Exercise the actor's actual curl command against a loopback HTTP server."""

import os
import re
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("response_delay,response_status", [(0, 200), (2.5, 200), (0, 500)])
def test_http_connection_precedes_local_process_hold(tmp_path, response_delay, response_status):
    shell = shutil.which("powershell.exe")
    curl = shutil.which("curl.exe")
    if not shell or not curl or os.name != "nt":
        pytest.skip("Windows actor and native curl integration")
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, time.monotonic()))
            time.sleep(response_delay)
            self.send_response(response_status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            self.wfile.flush()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source = (ROOT / "scripts/run_training_http.ps1").read_text(encoding="utf-8")
    # Use the exact native invocation, changing only the test URL to loopback.
    command = re.search(
        r"    \$status=& \$curl .*?    Write-Output \"HTTP_REQUEST_OK[^\n]*", source, re.S,
    )
    assert command is not None
    harness = tmp_path / "curl-lifetime.ps1"
    harness.write_text(
        "$ErrorActionPreference='Stop'\n"
        + "$curl='" + curl.replace("'", "''") + "'\n"
        + f"$index=1\n$url='http://127.0.0.1:{server.server_port}/beacon?run=unit&n=1'\n"
        + command.group(0)
        + "\n",
        encoding="utf-8",
    )
    try:
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
            capture_output=True, text=True, timeout=20,
        )
        exited = time.monotonic()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert len(requests) == 1
    assert requests[0][0] == "/beacon?run=unit&n=1"
    if response_status != 200:
        assert result.returncode != 0, "Successful local transfers must not hide HTTP failure"
        assert "HTTP_REQUEST_OK" not in result.stdout
        assert "HTTP_ACTION_COMPLETE" not in result.stdout
        return
    assert result.returncode == 0, result.stderr
    assert "HTTP_REQUEST_OK seq=1 status=200" in result.stdout
    assert exited - requests[0][1] - response_delay >= 1.8, (
        "curl exited immediately after HTTP; the parent shell's sleep cannot keep it alive"
    )
