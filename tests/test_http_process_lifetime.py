"""Run the full async actor against loopback and observe its native curl processes."""

import ctypes
import json
import os
import shutil
import subprocess
import threading
import time
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]


class ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
    ]


class CurlProcesses:
    """Retain Windows query handles so exit times survive process termination."""

    def __init__(self):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateToolhelp32Snapshot": ([wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
            "Process32FirstW": ([wintypes.HANDLE, ctypes.POINTER(ProcessEntry)], wintypes.BOOL),
            "Process32NextW": ([wintypes.HANDLE, ctypes.POINTER(ProcessEntry)], wintypes.BOOL),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "GetProcessTimes": (
                [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)], wintypes.BOOL,
            ),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes = arguments
            function.restype = result
        self.handles = {}

    def observe(self, parent_pid):
        snapshot = self.kernel.CreateToolhelp32Snapshot(0x00000002, 0)
        assert snapshot != ctypes.c_void_p(-1).value, ctypes.WinError(ctypes.get_last_error())
        try:
            entry = ProcessEntry()
            entry.dwSize = ctypes.sizeof(entry)
            present = self.kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while present:
                if (entry.th32ParentProcessID == parent_pid
                        and entry.szExeFile.casefold() == "curl.exe"
                        and entry.th32ProcessID not in self.handles):
                    handle = self.kernel.OpenProcess(0x1000, False, entry.th32ProcessID)
                    if handle:
                        self.handles[entry.th32ProcessID] = handle
                present = self.kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            self.kernel.CloseHandle(snapshot)

    def lifetimes(self):
        times = []
        for handle in self.handles.values():
            created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
            assert self.kernel.GetProcessTimes(
                handle, ctypes.byref(created), ctypes.byref(exited),
                ctypes.byref(kernel), ctypes.byref(user),
            ), ctypes.WinError(ctypes.get_last_error())
            times.append(tuple(
                ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 10_000_000
                - 11_644_473_600 for value in (created, exited)
            ))
        return sorted(times)

    def close(self):
        for handle in self.handles.values():
            self.kernel.CloseHandle(handle)


@pytest.mark.parametrize("response_delay,response_status", [(0, 200), (2.5, 200), (0, 500)])
def test_full_async_actor_preserves_schedule_and_native_process_hold(
    tmp_path, response_delay, response_status,
):
    shell = shutil.which("powershell.exe")
    if not shell or not shutil.which("curl.exe") or os.name != "nt":
        pytest.skip("Windows actor and native curl integration")
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            record = {"path": self.path, "arrived": time.time()}
            requests.append(record)
            time.sleep(response_delay)
            self.send_response(response_status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            self.wfile.flush()
            record["responded"] = time.time()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source = (ROOT / "scripts/run_training_http.ps1").read_text(encoding="utf-8-sig")
    endpoint = "http://10.40.0.10:8081"
    assert source.count(endpoint) == 1
    actor = tmp_path / "run_training_http.ps1"
    # Execute every original statement, changing only the endpoint to our server.
    actor.write_text(source.replace(endpoint, f"http://127.0.0.1:{server.server_port}"),
                     encoding="utf-8-sig")
    processes = CurlProcesses()
    try:
        with subprocess.Popen(
            [shell, "-NoProfile", "-NonInteractive", "-File", str(actor),
             "-RunNonce", "unit_async_hold", "-Count", "2", "-GapsCsv", "0.7",
             "-VariantIndex", "7"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "TEMP": str(tmp_path)}, creationflags=subprocess.CREATE_NO_WINDOW,
        ) as process:
            deadline = time.monotonic() + 30
            while process.poll() is None and time.monotonic() < deadline:
                processes.observe(process.pid)
                time.sleep(0.01)
            if process.poll() is None:
                process.kill()
                pytest.fail("Full HTTP actor exceeded the 30-second test deadline")
            stdout, stderr = process.communicate(timeout=5)
            returncode = process.returncode
        lifetimes = processes.lifetimes()
    finally:
        processes.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    if response_status != 200:
        # After the first failed transfer, the actor cancels pending native
        # processes. The second launched curl can be killed before its GET.
        assert 1 <= len(requests) <= 2, (stdout, stderr)
        assert "HTTP_REQUEST_LAUNCHED seq=1" in stdout
        assert "HTTP_REQUEST_LAUNCHED seq=2" in stdout
        assert "CURL_RESULT seq=1 exit=22 status=500" in stdout
        assert returncode != 0, "Local transfers must not hide a failed HTTP action"
        assert "HTTP request 1 failed" in stderr
        assert "HTTP_REQUEST_OK" not in stdout
        assert "HTTP_ACTION_COMPLETE" not in stdout
        assert all(exited > started for started, exited in lifetimes), (
            "Failure cleanup must terminate every observed native curl process"
        )
        assert any(parse_qs(urlsplit(r["path"]).query).get("n") == ["1"] for r in requests)
        for request in requests:
            parsed = urlsplit(request["path"])
            query = parse_qs(parsed.query)
            assert parsed.path == "/beacon"
            assert query["run"] == ["unit_async_hold"] and query["v"] == ["7"]
            assert query["n"] in (["1"], ["2"])
        return

    assert len(requests) == 2, (stdout, stderr)
    requests.sort(key=lambda item: int(parse_qs(urlsplit(item["path"]).query)["n"][0]))
    for index, request in enumerate(requests, 1):
        parsed = urlsplit(request["path"])
        assert parsed.path == "/beacon"
        assert parse_qs(parsed.query) == {
            "run": ["unit_async_hold"], "v": ["7"], "n": [str(index)],
        }
        assert f"HTTP_REQUEST_LAUNCHED seq={index}" in stdout
    assert returncode == 0, stderr
    assert "HTTP_ACTION_COMPLETE count=2 nonce=unit_async_hold" in stdout
    assert len(lifetimes) == 2, "Observe both real curl processes independently of the parent shell"
    start_gap = lifetimes[1][0] - lifetimes[0][0]
    assert 0.55 <= start_gap <= 1.15, f"Frozen 0.7s launch gap became {start_gap:.3f}s"
    for index, ((started, exited), request) in enumerate(zip(lifetimes, requests, strict=True), 1):
        assert f"HTTP_REQUEST_OK seq={index} status=200" in stdout
        assert started <= request["arrived"] <= request["responded"] <= exited
        assert exited - request["responded"] >= 1.8, (
            "Each native curl process must remain alive after HTTP, independently of parent sleep"
        )
    assert lifetimes[1][0] < lifetimes[0][1], "The local hold must not serialize actor launches"
    print(json.dumps({
        "response_delay": response_delay, "response_status": response_status,
        "native_start_gap_seconds": start_gap,
        "native_hold_after_http_seconds": [
            exited - request["responded"]
            for (_, exited), request in zip(lifetimes, requests, strict=True)
        ],
    }))
