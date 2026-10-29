"""Durable and fail-closed window reservation behavior, independent of collector UI."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from ml.collection_windows import bucket_used, reserve_bucket

ROOT = Path(__file__).resolve().parents[1]
BUCKET = datetime(2026, 10, 28, 0, 5, tzinfo=UTC)
ASSET = "WIN11-TARGET"


def receipt_folder(
    root: Path,
    *,
    relative: str = "evidence/scenario-runs",
    state: str = "FINALIZED",
    receipt: Any = None,
    truth: Any = None,
) -> Path:
    folder = root / relative / "EARLIER-RUN"
    folder.mkdir(parents=True)
    if receipt is None:
        receipt = {
            "run_id": "EARLIER-RUN",
            "status": "COMPLETED",
            "aggregation_window_start": BUCKET.isoformat(),
        }
    if truth is None:
        truth = {"host": ASSET}
    (folder / "execution_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    (folder / "ground_truth.json").write_text(json.dumps(truth), encoding="utf-8")
    (folder / ".collection_state.json").write_text(
        json.dumps({"status": state}), encoding="utf-8"
    )
    return folder


def test_only_one_concurrent_reservation_claim_wins(tmp_path: Path) -> None:
    count = 8
    ready = threading.Barrier(count)

    def claim(index: int) -> bool:
        ready.wait(timeout=15)
        try:
            reserve_bucket(tmp_path, ASSET, BUCKET, f"CONCURRENT-{index}")
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=count) as executor:
        winners = list(executor.map(claim, range(count)))

    assert sum(winners) == 1
    assert bucket_used(tmp_path, ASSET, BUCKET)


def test_reservation_is_visible_after_fresh_process_restart(tmp_path: Path) -> None:
    reserve_bucket(tmp_path, ASSET, BUCKET, "BEFORE-RESTART")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json,sys; from pathlib import Path; from datetime import datetime; "
            "from ml.collection_windows import bucket_used; "
            "print(json.dumps(bucket_used(Path(sys.argv[1]),sys.argv[2],"
            "datetime.fromisoformat(sys.argv[3]))))",
            str(tmp_path),
            ASSET.casefold(),
            BUCKET.isoformat(),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert json.loads(result.stdout) is True
    with pytest.raises(ValueError):
        reserve_bucket(tmp_path, ASSET.casefold(), BUCKET, "AFTER-RESTART")


def test_lost_reservation_index_is_recovered_from_receipt(tmp_path: Path) -> None:
    reserve_bucket(tmp_path, ASSET, BUCKET, "EARLIER-RUN")
    receipt_folder(tmp_path)
    index_files = list((tmp_path / "evidence/bucket-reservations").glob("*.json"))
    assert len(index_files) == 1
    index_files[0].unlink()

    assert bucket_used(tmp_path, ASSET.casefold(), BUCKET)
    assert not bucket_used(tmp_path, ASSET, BUCKET + timedelta(minutes=5))


def test_aborted_run_still_burns_its_bucket(tmp_path: Path) -> None:
    receipt_folder(tmp_path, state="ABORTED")

    assert bucket_used(tmp_path, ASSET, BUCKET)
    assert not bucket_used(tmp_path, "ANOTHER-TARGET", BUCKET)


def test_quarantined_run_still_burns_its_bucket_after_index_loss(tmp_path: Path) -> None:
    from test_collection_acceptance import _collect_run, _prepare_collection_root

    from ml.scenario_collection import quarantine_run

    archive, sources, catalog = _prepare_collection_root(tmp_path)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == "ACCOUNT-BENIGN-NORMAL-LOGON")
    run_id = _collect_run(tmp_path, archive, sources, scenario, sequence=0, repeat=0)
    directory = tmp_path / "evidence/scenario-runs" / run_id
    receipt = json.loads((directory / "execution_receipt.json").read_text())
    host = json.loads((directory / "ground_truth.json").read_text())["host"]
    bucket = datetime.fromisoformat(receipt["aggregation_window_start"])
    quarantine_run(run_id, tmp_path, "synthetic test")
    for path in (tmp_path / "evidence/bucket-reservations").glob("*.json"):
        path.unlink()
    assert bucket_used(tmp_path, host, bucket)
    assert not bucket_used(tmp_path, "ANOTHER-TARGET", bucket)


def test_incomplete_quarantine_fails_closed(tmp_path: Path) -> None:
    receipt_folder(tmp_path, relative="evidence/quarantine", state="QUARANTINED")
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(tmp_path, ASSET, BUCKET)


def test_other_asset_and_next_bucket_can_be_reserved(tmp_path: Path) -> None:
    reserve_bucket(tmp_path, ASSET, BUCKET, "FIRST")
    reserve_bucket(tmp_path, "ANOTHER-TARGET", BUCKET, "OTHER-ASSET")
    reserve_bucket(tmp_path, ASSET, BUCKET + timedelta(minutes=5), "NEXT-BUCKET")

    assert bucket_used(tmp_path, ASSET, BUCKET)
    assert bucket_used(tmp_path, "ANOTHER-TARGET", BUCKET)
    assert bucket_used(tmp_path, ASSET, BUCKET + timedelta(minutes=5))


@pytest.mark.parametrize(
    ("receipt", "truth"),
    [
        ([], {"host": ASSET}),
        ({}, {"host": ASSET}),
        ({"aggregation_window_start": "not-a-timestamp"}, {"host": ASSET}),
        ({"aggregation_window_start": 12345}, {"host": ASSET}),
        ({"aggregation_window_start": "2026-10-28T00:05:00"}, {"host": ASSET}),
        ({"aggregation_window_start": BUCKET.isoformat()}, {}),
        ({"aggregation_window_start": BUCKET.isoformat()}, {"host": None}),
        ({"aggregation_window_start": BUCKET.isoformat()}, {"host": ""}),
    ],
    ids=[
        "non-object-receipt", "missing-bucket", "invalid-time", "non-string-time",
        "timezone-missing", "missing-host", "non-string-host", "empty-host",
    ],
)
def test_malformed_receipt_recovery_fails_closed(
    tmp_path: Path, receipt: Any, truth: Any,
) -> None:
    receipt_folder(tmp_path, receipt=receipt, truth=truth)

    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(tmp_path, ASSET, BUCKET)


def test_truncated_receipt_recovery_fails_closed(tmp_path: Path) -> None:
    folder = receipt_folder(tmp_path)
    (folder / "execution_receipt.json").write_text('{"aggregation_window_start":', encoding="utf-8")

    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(tmp_path, ASSET, BUCKET)
