"""Bounded inert HTTP workflows for the isolated lab, never a remote executor."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "lab-http-workflow-v2"
FIELDS = {
    "profile_version",
    "transport",
    "endpoint",
    "expected_action_count",
    "base_intervals_seconds",
    "http_methods_csv",
    "request_body_bytes_csv",
    "response_body_bytes_csv",
}


def action_rows(parameters: dict) -> list[tuple[str, int, int]]:
    count = parameters.get("expected_action_count")
    if type(count) is not int or not 1 <= count <= 64:
        raise ValueError("HTTP workflow count must be an integer in1..64")
    columns = []
    for key in ("http_methods_csv", "request_body_bytes_csv", "response_body_bytes_csv"):
        text = parameters.get(key)
        if not isinstance(text, str) or len(text) > 2048:
            raise ValueError("HTTP workflow requires bounded CSV columns")
        values = text.split(",")
        if len(values) != count:
            raise ValueError("HTTP workflow columns do not match the frozen action count")
        columns.append(values)
    result = []
    for method, upload, download in zip(*columns, strict=True):
        if (
            method not in {"GET", "POST"}
            or not re.fullmatch(r"0|[1-9][0-9]{0,4}", upload)
            or not re.fullmatch(r"[1-9][0-9]{0,4}", download)
        ):
            raise ValueError("unsupported method or payload size")
        sent, received = int(upload), int(download)
        if (
            not 0 <= sent <= 65536
            or not 1 <= received <= 65536
            or (method == "GET" and sent != 0)
            or (method == "POST" and sent == 0)
        ):
            raise ValueError("HTTP payload/method contract is invalid")
        result.append((method, sent, received))
    return result


def workflow_intervals(profile: dict) -> list[float]:
    if (
        set(profile) != FIELDS
        or profile.get("profile_version") != VERSION
        or profile.get("transport") != "http"
        or profile.get("endpoint") != "http://10.40.0.10:8081/beacon"
    ):
        raise ValueError("invalid HTTP workflow identity/isolated endpoint")
    actions = action_rows(profile)
    text = profile["base_intervals_seconds"]
    if not isinstance(text, str):
        raise ValueError("HTTP workflow intervals must be CSV text")
    gaps = [] if text == "" else [float(x) for x in text.split(",")]
    if (
        len(gaps) != len(actions) - 1
        or any(not math.isfinite(x) or not 1 <= x <= 300 for x in gaps)
        or sum(gaps) * 1.3 >= 240
    ):
        raise ValueError("HTTP workflow timing exceeds its bounded capture window")
    return gaps


def declared_workflow(template: str, label: str) -> dict:
    """Fixed overlapping lab workloads; no method/size alone encodes the label."""
    patterns = {
        ("tcp-poll", "benign"): (
            "GPGPGPGP",
            "10,10,10,10,10,10,10",
            [0, 128, 0, 128, 0, 128, 0, 128],
            [256] * 8,
        ),
        ("tcp-poll", "malicious"): (
            "GPGPGPGP",
            "10,10,10,10,10,10,10",
            [0, 1024, 0, 2048, 0, 4096, 0, 2048],
            [256] * 8,
        ),
        ("tcp-transfer", "benign"): (
            "GGPP",
            "3,12,3",
            [0, 0, 16384, 16384],
            [8192, 8192, 128, 128],
        ),
        ("tcp-transfer", "malicious"): (
            "GPGP",
            "3,12,3",
            [0, 16384, 0, 16384],
            [8192, 128, 8192, 128],
        ),
        ("tcp-api", "benign"): (
            "GPPGGPPG",
            "2,2,10,2,2,10,2",
            [0, 512, 1024, 0, 0, 512, 1024, 0],
            [512] * 8,
        ),
        ("tcp-api", "malicious"): (
            "GPGPGPGP",
            "3,10,2,8,3,10,2",
            [0, 512, 0, 1024, 0, 512, 0, 1024],
            [512] * 8,
        ),
        ("tcp-retry", "benign"): (
            "GGGPPP",
            "5,10,5,10,5",
            [0, 0, 0, 512, 512, 512],
            [1024, 1024, 1024, 128, 128, 128],
        ),
        ("tcp-retry", "malicious"): (
            "GPGPGP",
            "5,10,5,10,5",
            [0, 512, 0, 512, 0, 512],
            [1024, 128, 1024, 128, 1024, 128],
        ),
    }
    if (template, label) not in patterns:
        raise ValueError("unknown predeclared HTTP template/label")
    methods, gaps, sent, received = patterns[(template, label)]
    result = {
        "profile_version": VERSION,
        "transport": "http",
        "endpoint": "http://10.40.0.10:8081/beacon",
        "expected_action_count": len(methods),
        "base_intervals_seconds": gaps,
        "http_methods_csv": ",".join("GET" if c == "G" else "POST" for c in methods),
        "request_body_bytes_csv": ",".join(str(x) for x in sent),
        "response_body_bytes_csv": ",".join(str(x) for x in received),
    }
    workflow_intervals(result)
    return result


def validate_http_transaction(payload: dict, parameters: dict, ordinal: int) -> None:
    method, _, length = action_rows(parameters)[ordinal - 1]
    http = payload.get("http") or {}
    uri = urlsplit(str(http.get("url", "")))
    expected = {
        "run": [parameters["run_nonce"]],
        "v": [str(parameters["variant_index"])],
        "n": [str(ordinal)],
        "z": [str(length)],
    }
    if (
        uri.scheme
        or uri.netloc
        or uri.path != "/beacon"
        or parse_qs(uri.query, keep_blank_values=True) != expected
        or str(http.get("http_method", "")).upper() != method
        or type(http.get("status")) is not int
        or http["status"] != 200
        or type(http.get("length")) is not int
        or http["length"] != length
    ):
        raise ValueError("HTTP EVE transaction contradicts the frozen method/response contract")


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        # Only structured observations below are emitted; no request bodies.
        return

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        self.close_connection = True
        uri = urlsplit(self.path)
        query = parse_qs(uri.query, keep_blank_values=True)
        purpose = "planned-action"
        if set(query) in ({"preflight"}, {"enrollment"}):
            purpose = next(iter(query))
            values = query[purpose]
            valid = len(values) == 1 and (
                re.fullmatch(r"[A-Za-z0-9_-]{8,64}", values[0]) is not None
                if purpose == "preflight" else values == ["1"]
            )
            if (
                not valid or self.command != "GET"
                or self.headers.get("Content-Length", "0") != "0"
                or self.headers.get("Transfer-Encoding")
            ):
                self.send_error(400)
                return
            # Neutral telemetry setup remains distinct from labelled actions.
            # Original URI stays in EVE; no planned nonce/ordinal is fabricated.
            query = {"run": [values[0] if purpose == "preflight" else "neutral-enrollment"],
                     "v": ["0"], "n": ["1"], "z": ["16"]}
        if (
            len(self.path) > 1024
            or uri.path != "/beacon"
            or set(query) not in ({"run", "v", "n"}, {"run", "v", "n", "z"})
            or any(len(v) != 1 for v in query.values())
            or re.fullmatch(r"[A-Za-z0-9_-]{8,64}", query.get("run", [""])[0]) is None
            or re.fullmatch(r"[0-9]{1,6}", query.get("v", [""])[0]) is None
            or re.fullmatch(r"[0-9]{1,2}", query.get("n", [""])[0]) is None
            or re.fullmatch(r"[0-9]{1,5}", query.get("z", ["16"])[0]) is None
        ):
            self.send_error(400)
            return
        length = int(query.get("z", ["16"])[0])
        try:
            upload = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if (
            self.headers.get("Transfer-Encoding")
            or not 0 <= upload <= 65536
            or not 1 <= length <= 65536
            or not 1 <= int(query["n"][0]) <= 64
            or (self.command == "GET" and upload)
        ):
            self.send_error(400)
            return
        self.connection.settimeout(5)
        body = self.rfile.read(upload)
        if len(body) != upload:
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"Z" * length)
        observation = {
            "purpose": purpose,
            "at": datetime.now(UTC).isoformat(),
            "method": self.command,
            "request_bytes": len(body),
            "response_bytes": length,
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "run": query["run"][0],
            "sequence": int(query["n"][0]),
        }
        self.server.observations.append(observation)
        if self.server.emit_observations:
            print(json.dumps(observation, sort_keys=True), flush=True)


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, *, emit_observations=False):
        self.observations = []
        self.emit_observations = emit_observations
        super().__init__(address, LabHandler)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", choices=("10.40.0.10", "127.0.0.1"), default="10.40.0.10")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("lab service requires an unprivileged port")
    server = LabHTTPServer((args.bind, args.port), emit_observations=True)
    print(
        json.dumps({"service": "DATN inert HTTP workflows", "bind": args.bind, "port": args.port}),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
