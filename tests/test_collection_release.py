from __future__ import annotations

import json

import pytest

from ml import collection_release as release


def test_dataset_rejects_mixed_candidate_runtime_even_when_contract_matches(tmp_path):
    candidate = {"tag": "candidate-test", "commit": "a" * 40, "node_version": "v1"}
    for rid in ("UNIT-ONE", "UNIT-TWO"):
        p = tmp_path / rid
        p.mkdir()
        (p / ".collection_state.json").write_text(
            json.dumps(
                {
                    "collection_candidate": candidate,
                    "collection_candidate_sha256": release.digest(candidate),
                }
            )
        )
    assert (
        release.summarize_candidates(tmp_path, ["UNIT-ONE", "UNIT-TWO"], "candidate-test")
        == candidate
    )
    candidate["node_version"] = "v2"
    (tmp_path / "UNIT-TWO/.collection_state.json").write_text(
        json.dumps(
            {
                "collection_candidate": candidate,
                "collection_candidate_sha256": release.digest(candidate),
            }
        )
    )
    with pytest.raises(release.ReleaseError, match="mixed candidate"):
        release.summarize_candidates(tmp_path, ["UNIT-ONE", "UNIT-TWO"], "candidate-test")


def test_dataset_requires_candidate_bound_to_declared_tag(tmp_path):
    (tmp_path / "UNIT-ONE").mkdir()
    (tmp_path / "UNIT-ONE/.collection_state.json").write_text("{}")
    with pytest.raises(release.ReleaseError, match="candidate"):
        release.summarize_candidates(tmp_path, ["UNIT-ONE"], "candidate-test")


def test_frozen_snapshot_rejects_changes():
    snapshot = {"version": "collection-acceptance-v1", "candidate": {"commit": "a" * 40}}
    snapshot["record_sha256"] = release.digest(snapshot)
    state = {"collection_release": snapshot, "collection_release_sha256": release.digest(snapshot)}
    release.verify_frozen_acceptance(state)
    state["collection_release"]["candidate"]["commit"] = "b" * 40
    with pytest.raises(release.ReleaseError):
        release.verify_frozen_acceptance(state)


def test_trainable_requires_configured_existing_acceptance(tmp_path):
    with pytest.raises(release.ReleaseError):
        release.assert_collection_authorized(
            {"collection_release_path": "accept.json"}, tmp_path, "trainable"
        )
    assert release.assert_collection_authorized({}, tmp_path, "pilot") is None


def test_candidate_requires_clean_git_and_annotated_tag(tmp_path):
    with pytest.raises(release.ReleaseError):
        release.capture_candidate(tmp_path, "candidate-test")


def test_receipt_cannot_be_bare_pass(tmp_path):
    path = tmp_path / "accept.json"
    path.write_text(json.dumps({"status": "PASS"}), encoding="utf-8")
    with pytest.raises(release.ReleaseError):
        release.assert_collection_authorized(
            {"collection_release_path": str(path)}, tmp_path, "trainable"
        )


def test_backup_rejects_path_traversal(tmp_path):
    import io
    import tarfile

    archive = tmp_path / "backup.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        tar.addfile(member, io.BytesIO(b"x"))
    destination = tmp_path / "restore"
    destination.mkdir()
    with pytest.raises(release.ReleaseError, match="unsafe"):
        release._extract_backup(archive, destination)
    assert not (tmp_path / "escape").exists()


def test_remote_tag_requires_annotated_object_and_peeled_commit(monkeypatch, tmp_path):
    candidate = {"tag": "candidate-a", "tag_object": "a" * 40, "commit": "b" * 40}
    ref = "refs/tags/candidate-a"
    monkeypatch.setattr(release, "_git", lambda *args: f"{'a' * 40}\t{ref}\n{'b' * 40}\t{ref}^{{}}")
    release.verify_remote_candidate(tmp_path, candidate)
    monkeypatch.setattr(release, "_git", lambda *args: f"{'a' * 40}\t{ref}")
    with pytest.raises(release.ReleaseError, match="remote"):
        release.verify_remote_candidate(tmp_path, candidate)


def test_source_design_rejects_missing_contract(tmp_path):
    with pytest.raises(release.ReleaseError):
        release._check_design(tmp_path)


def test_preflight_rejects_pasted_report_without_events(tmp_path):
    capture = tmp_path / "archives-fresh.jsonl"
    capture.write_text("{}\n", encoding="utf-8")
    with pytest.raises(release.ReleaseError):
        release._check_preflight_capture(capture, {"canary_id": "test-canary"})


def test_authorization_revalidates_artifacts_and_detects_mismatch(tmp_path, monkeypatch):
    candidate = {"tag": "candidate-test", "commit": "a" * 40}
    record = {
        "version": "collection-acceptance-v1",
        "candidate": candidate,
        "pilots": [{"run_id": f"PILOT-{index}"} for index in range(4)],
        "preflight_directory": str(tmp_path / "preflight"),
        "backup": {"directory": str(tmp_path / "backup")},
    }
    record["record_sha256"] = release.digest(record)
    path = tmp_path / "accept.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(release, "capture_candidate", lambda *_: candidate)
    calls = []

    def verify(*args):
        calls.append(args)
        return record

    monkeypatch.setattr(release, "create_acceptance", verify)
    assert (
        release.assert_collection_authorized(
            {"collection_release_path": str(path)}, tmp_path, "trainable"
        )
        == record
    )
    assert len(calls) == 1
    monkeypatch.setattr(release, "create_acceptance", lambda *_: {})
    with pytest.raises(release.ReleaseError, match="differs"):
        release.assert_collection_authorized(
            {"collection_release_path": str(path)}, tmp_path, "trainable"
        )
