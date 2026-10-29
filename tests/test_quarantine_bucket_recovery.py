"""Conservative recovery of quarantined damaged receipts."""

import json
from datetime import timedelta

import pytest
from test_collection_acceptance import COLLECTION_BASE, _collect_run, _prepare_collection_root

from ml.collection_windows import bucket_used
from ml.scenario_collection import quarantine_run


@pytest.mark.parametrize("mode", ["changed", "missing"])
def test_changed_or_missing_receipt_after_index_loss(damaged, mode):
    root, directory, host, receipt = damaged
    for path in (root / "evidence/bucket-reservations").glob("*.json"):
        path.unlink()
    path = directory / "execution_receipt.json"
    if mode == "missing":
        path.unlink()
    else:
        receipt["aggregation_window_start"] = "2027-01-01T00:00:00Z"
        path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_recorded_origin_newlines(damaged, newline):
    import hashlib

    root, directory, host, receipt = damaged
    original = (
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").replace("\n", newline).encode()
    )
    digest = hashlib.sha256(original).hexdigest()
    path = directory / "collection_metadata.json"
    metadata = json.loads(path.read_text())
    metadata["execution_receipt_sha256"] = digest
    path.write_text(json.dumps(metadata))
    manifest = directory / "checksums.sha256"
    entries = dict(line.split("  ", 1)[::-1] for line in manifest.read_text().splitlines())
    entries["execution_receipt.json"] = digest
    entries["collection_metadata.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest.write_text("".join(f"{value}  {name}\n" for name, value in entries.items()))
    assert not bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


@pytest.fixture
def damaged(tmp_path):
    archive, sources, catalog = _prepare_collection_root(tmp_path)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == "ACCOUNT-BENIGN-NORMAL-LOGON")
    run_id = _collect_run(tmp_path, archive, sources, scenario, sequence=0, repeat=0)
    directory = tmp_path / "evidence/scenario-runs" / run_id
    receipt = json.loads((directory / "execution_receipt.json").read_text())
    draft = json.loads((directory / "ground_truth.json").read_text())
    (directory / "execution_receipt.json").write_text("{broken-receipt", encoding="utf-8")
    quarantine_run(run_id, tmp_path, "damaged synthetic receipt")
    return tmp_path, tmp_path / "evidence/quarantine" / run_id, draft["host"], receipt


def test_damaged_quarantined_receipt_allows_later_bucket_preserving_original(damaged):
    root, directory, host, receipt = damaged
    assert not bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))
    from datetime import datetime

    assert bucket_used(root, host, datetime.fromisoformat(receipt["aggregation_window_start"]))
    assert (directory / "execution_receipt.json").read_text() == "{broken-receipt"


@pytest.mark.parametrize(
    "source", ["collection_metadata.json", "start-contract.json", ".collection_state.json"]
)
def test_missing_recovery_evidence_blocks(damaged, source):
    root, directory, host, _ = damaged
    (directory / source).unlink()
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


@pytest.mark.parametrize(
    "source", ["collection_metadata.json", "ground_truth.json", ".collection_state.json"]
)
def test_conflicting_recovery_evidence_blocks(damaged, source):
    root, directory, host, _ = damaged
    data = json.loads((directory / source).read_text())
    data["run_id"] = "EDITED-RUN"
    (directory / source).write_text(json.dumps(data))
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


def test_recovery_requires_original_reservation(damaged):
    root, _, host, _ = damaged
    for path in (root / "evidence/bucket-reservations").glob("*.json"):
        path.unlink()
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


def test_parseable_changed_receipt_uses_frozen_ownership(damaged):
    from datetime import datetime

    root, directory, host, receipt = damaged
    changed = dict(receipt, aggregation_window_start="2027-01-01T00:00:00Z")
    (directory / "execution_receipt.json").write_text(json.dumps(changed))
    assert not bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))
    assert bucket_used(root, host, datetime.fromisoformat(receipt["aggregation_window_start"]))


def test_missing_quarantine_marker_blocks(damaged):
    root, directory, host, _ = damaged
    (directory / "quarantine.json").unlink()
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


def test_linked_recovery_source_blocks(damaged, tmp_path):
    root, directory, host, _ = damaged
    source = directory / "collection_metadata.json"
    outside = tmp_path.parent / (tmp_path.name + "-metadata.json")
    outside.write_bytes(source.read_bytes())
    source.unlink()
    try:
        source.symlink_to(outside)
    except OSError:
        pytest.skip("creating symlinks is unavailable")
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


@pytest.mark.parametrize(
    "source", ["checksums.sha256", "execution-parameters.json", "execution_receipt.json"]
)
def test_sources_are_revalidated_after_successful_recovery(damaged, source):
    root, directory, host, _ = damaged
    assert not bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))
    path = directory / source
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


@pytest.mark.parametrize("field", ["run_id", "asset", "bucket_start"])
def test_conflicting_reservation_blocks(damaged, field):
    root, _, host, _ = damaged
    path = next((root / "evidence/bucket-reservations").glob("*.json"))
    data = json.loads(path.read_text())
    data[field] = "EDITED"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


def test_recovery_record_hash_mutation_blocks(damaged):
    root, directory, host, _ = damaged
    assert not bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))
    path = directory / "bucket_recovery.json"
    record = json.loads(path.read_text())
    record["source_sha256"]["execution_receipt.json"] = "0" * 64
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))


@pytest.mark.parametrize(
    "field", ["run_id", "aggregation_window_start", "frozen_parameters_sha256"]
)
def test_edited_state_receipt_cannot_reassign_ownership(damaged, field):
    root, directory, host, _ = damaged
    path = directory / ".collection_state.json"
    state = json.loads(path.read_text())
    state["execution_receipt"][field] = "EDITED"
    path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="cannot recover collection bucket"):
        bucket_used(root, host, COLLECTION_BASE + timedelta(hours=1))
