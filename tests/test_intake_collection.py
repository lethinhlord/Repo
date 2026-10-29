"""Generated collector watermark integration checks; not lab evidence."""

import json
from datetime import timedelta

import pytest
import test_collection_acceptance as acceptance

from ml import scenario_collection as collector


def collect(root):
    archive, source, catalog = acceptance._prepare_collection_root(root)
    scenario = next(row for row in catalog.scenarios if row.family == "account")
    return acceptance._collect_run(root, archive, source, scenario, sequence=0, repeat=0)


def test_cold_collector_after_deadline_refuses(tmp_path, monkeypatch):
    def late(run_id, root, *, now):
        return collector.finalize_run(run_id, root, now=now + timedelta(seconds=1))

    monkeypatch.setattr(acceptance, "finalize_run", late)
    with pytest.raises(collector.CollectionError, match="deadline.*checkpoint"):
        collect(tmp_path)
    assert not list((tmp_path / "data/raw").glob("*/incidents.jsonl"))


def test_sealed_retry_cannot_enlarge_capture(tmp_path, monkeypatch):
    original = collector._derive_account

    def retry(run_id, root, *, now):
        def fail(*args, **kwargs):
            raise collector.CollectionError("injected post-seal derivation interruption")

        monkeypatch.setattr(collector, "_derive_account", fail)
        with pytest.raises(collector.CollectionError, match="post-seal"):
            collector.finalize_run(run_id, root, now=now)
        monkeypatch.setattr(collector, "_derive_account", original)
        evidence = root / "evidence/scenario-runs" / run_id
        frozen = (evidence / "archive_capture.jsonl").read_bytes()
        checkpoint = (evidence / "intake_checkpoint.json").read_bytes()
        result = collector.finalize_run(run_id, root, now=now + timedelta(seconds=30))
        assert (evidence / "archive_capture.jsonl").read_bytes() == frozen
        assert (evidence / "intake_checkpoint.json").read_bytes() == checkpoint
        return result

    monkeypatch.setattr(acceptance, "finalize_run", retry)
    run_id = collect(tmp_path)
    # Backup verification deliberately requires only saved evidence.
    (tmp_path / "archives.json").unlink()
    assert collector.validate_run(run_id, tmp_path)["status"] == "VALID"


def test_sealed_retry_rejects_late_original_bucket(tmp_path, monkeypatch):
    original = collector._derive_account

    def retry(run_id, root, *, now):
        def fail(*args, **kwargs):
            raise collector.CollectionError("post-seal interruption")

        monkeypatch.setattr(collector, "_derive_account", fail)
        with pytest.raises(collector.CollectionError, match="post-seal"):
            collector.finalize_run(run_id, root, now=now)
        monkeypatch.setattr(collector, "_derive_account", original)
        evidence = root / "evidence/scenario-runs" / run_id
        frozen = (evidence / "archive_capture.jsonl").read_bytes()
        with (root / "archives.json").open("ab") as handle:
            handle.write(frozen)
        with pytest.raises(collector.CollectionError, match="late original-window"):
            collector.finalize_run(run_id, root, now=now + timedelta(seconds=30))
        assert (evidence / "archive_capture.jsonl").read_bytes() == frozen
        assert (evidence / "archive_capture-late.jsonl").read_bytes() == frozen
        raise collector.CollectionError("late-retry verified")

    monkeypatch.setattr(acceptance, "finalize_run", retry)
    with pytest.raises(collector.CollectionError, match="late-retry verified"):
        collect(tmp_path)


def test_frozen_checkpoint_tamper_rejected_even_with_refreshed_checksums(tmp_path):
    run_id = collect(tmp_path)
    evidence = tmp_path / "evidence/scenario-runs" / run_id
    checkpoint = evidence / "intake_checkpoint.json"
    payload = json.loads(checkpoint.read_text())
    payload["admitted_offset"] += 1
    checkpoint.write_text(json.dumps(payload))
    collector._write_checksums(evidence)
    with pytest.raises(collector.CollectionError, match="checkpoint"):
        collector.validate_run(run_id, tmp_path)


def test_online_exact_cutoff_agrees_with_collector(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from test_feature_state import raw_account_alert

    from api.app.feature_state import FeatureStateStore

    cutoff = datetime(2026, 10, 27, 0, 6, tzinfo=UTC).timestamp()
    monkeypatch.setattr("api.app.feature_state.time.time", lambda: cutoff)
    result = FeatureStateStore(tmp_path / "state.sqlite3").ingest(
        raw_account_alert("EXACT-CUTOFF", "2026-10-27T00:00:10Z", 4624),
    )
    assert "window:late_arrival" not in result.feature.incident.review_reasons
    assert "window:open" in result.feature.incident.review_reasons
