import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ml.preflight import verify_preflight_capture

START = datetime(2026, 11, 6, tzinfo=UTC)
NONCE = "CANARY-UNIT"


def canary_rows():
    """Synthetic channel fixture, not evidence that any VM has been exercised."""
    at = START + timedelta(seconds=10)
    native = at.strftime("%Y-%m-%d %H:%M:%S.%f")

    def win(eid, fields):
        return {
            "agent": {"name": "WIN11-TARGET"},
            "data": {
                "win": {
                    "system": {"eventID": str(eid), "systemTime": at.isoformat()},
                    "eventdata": fields,
                }
            },
        }

    rows = [
        win(
            eid,
            {
                "targetUserName": user,
                "logonType": kind,
                "ipAddress": "10.40.0.10" if kind == "3" else "127.0.0.1",
            },
        )
        for user, kind in [("datn_benign", "2"), ("datn_attack", "3")]
        for eid in (4624, 4625)
    ]
    for eid in (1, 3, 22):
        rows.append(
            win(
                eid,
                {
                    "processGuid": "GUID-CANARY",
                    "image": "powershell.exe",
                    "commandLine": NONCE,
                    "utcTime": native,
                },
            )
        )

    def sensor(payload):
        return {"agent": {"name": "NET-SENSOR"}, "full_log": json.dumps(payload)}

    def payload(port, fid, proto="TCP"):
        return {
            "timestamp": at.isoformat(),
            "flow_id": fid,
            "proto": proto,
            "src_ip": "10.20.0.10",
            "src_port": 50000 + fid,
            "dest_ip": "10.40.0.10",
            "dest_port": port,
        }

    def final(p):
        return {
            **p,
            "event_type": "flow",
            "flow": {
                "start": at.isoformat(),
                "end": (at + timedelta(seconds=1)).isoformat(),
                "bytes_toserver": 100,
                "bytes_toclient": 200,
            },
        }

    for i, port in enumerate((8080, 8081, 9001), 1):
        p = payload(port, i)
        rows.extend(
            [
                sensor(
                    {**p, "event_type": "http", "http": {"url": f"/?preflight={NONCE.lower()}"}}
                ),
                sensor(final(p)),
            ]
        )
    for i, (marker, domain, number) in enumerate(
        [(m, d, n) for m, d in [("b", "www.datn.test"), ("r", "beacon.datn.test")] for n in (1, 2)],
        10,
    ):
        p = payload(53, i, "UDP")
        name = f"{NONCE.lower()}-{marker}0-{number:02d}.{domain}"
        rows.extend(
            [
                sensor({**p, "event_type": "dns", "dns": {"type": "query", "rrname": name}}),
                sensor(
                    {
                        **p,
                        "src_ip": p["dest_ip"],
                        "dest_ip": p["src_ip"],
                        "src_port": 53,
                        "dest_port": p["src_port"],
                        "event_type": "dns",
                        "dns": {"type": "answer", "rrname": name},
                    }
                ),
                sensor(final(p)),
            ]
        )
    return rows


def test_preflight_positive_replays_exactly_and_missing_final_fails(tmp_path):
    path = tmp_path / "capture.jsonl"
    rows = canary_rows()
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    report = verify_preflight_capture(
        path, NONCE.lower(), START.isoformat(), (START + timedelta(minutes=5)).isoformat()
    )
    assert report["http_ports"] == [8080, 8081, 9001]
    assert report["final_connections"] == 7
    from ml.collection_release import ReleaseError, _check_preflight_capture

    _check_preflight_capture(path, report)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows[:-1]))
    with pytest.raises(ReleaseError, match="preflight"):
        _check_preflight_capture(path, report)


def test_empty_raw_cannot_be_certified_by_report(tmp_path: Path):
    raw = tmp_path / "capture.jsonl"
    raw.write_text("{}\n")
    with pytest.raises(ValueError):
        verify_preflight_capture(raw, "CANARY-UNIT", "2026-11-06T00:00:00Z", "2026-11-06T00:05:00Z")
