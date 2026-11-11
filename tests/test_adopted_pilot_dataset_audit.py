"""Synthetic retained-pilot regression; this does not certify a real lab run."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import test_acceptance_source_binding as binding
import test_official_collection_acceptance as official

from ml import build_dataset as builder
from ml import collection_release as release


def test_builder_cli_forwards_active_source_config(monkeypatch):
    called = {}

    def build(config_path, *, source_config_path=None):
        called.update(config=config_path, source=source_config_path)
        return {"dataset_hash_sha256": "synthetic"}

    monkeypatch.setattr(builder, "build_dataset", build)
    monkeypatch.setattr(sys, "argv", [
        "build_dataset", "--source-config", "operator-logs/collection-sources-active.yaml",
    ])
    builder.main()
    assert called == {
        "config": Path("ml/training_config.yaml"),
        "source": Path("operator-logs/collection-sources-active.yaml"),
    }


def test_old_pilots_and_challenge_remain_verified_with_new_trainable_collection(
    tmp_path, monkeypatch,
):
    archive, original, catalog, old_candidate, old, backup, _ = official.accept_official_lab(
        tmp_path, monkeypatch,
    )
    challenge = next(s for s in catalog.scenarios if s.purpose == "challenge")
    challenge_id = official.fixture._collect_run(
        tmp_path, archive, original, challenge, sequence=4, repeat=0, purpose="challenge",
    )
    source = binding.selected_source(tmp_path, original)
    candidate = {**old_candidate, "commit": "e" * 40, "tracked_files_sha256": "f" * 64}
    monkeypatch.setattr(release, "capture_candidate", lambda *args: candidate)
    # Migration policy itself has separate tests. Here its approved result is
    # the trust boundary while all collection and audit checks remain real.
    monkeypatch.setitem(sys.modules, "ml.collection_adoption", SimpleNamespace(
        verify_pilot_adoption=lambda *args: {"synthetic_policy": "approved"},
    ))
    output = tmp_path / "evidence/collection-acceptance.json"
    output.unlink()  # Disposable synthetic receipt only.
    release.create_acceptance(
        tmp_path, candidate["tag"], [p["run_id"] for p in old["pilots"]], backup,
        tmp_path / "operator-logs/preflight/UNIT", output, source_config_path=source,
    )
    create = official.fixture.create_run_draft

    def draft(*args, **kwargs):
        return create(*args, source_config_path=source, **kwargs)

    monkeypatch.setattr(official.fixture, "create_run_draft", draft)
    sequence = 5
    for repeat in (10, 11):
        for scenario in catalog.scenarios:
            if scenario.purpose == "trainable":
                official.fixture._collect_run(
                    tmp_path, archive, source, scenario, sequence=sequence, repeat=repeat,
                )
                sequence += 1
    report = official.fixture._audit(tmp_path, source)
    assert report["status"] == "READY", report["issues"]
    assert report["collection_candidate"] == candidate
    assert report["excluded_purpose_counts"] == {"pilot": 4, "challenge": 1}

    # Builder must consume the same active source as draft, START and audit.
    training = tmp_path / "ml/training_config.yaml"
    training_bytes = training.read_bytes()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(builder, "_git_commit", lambda: candidate["commit"])
    manifest = builder.build_dataset(Path("ml/training_config.yaml"), source_config_path=source)
    assert training.read_bytes() == training_bytes
    assert sum(manifest["record_counts"].values()) == 40
    assert manifest["challenge"]["record_count"] == 1
    assert manifest["collection_audit"]["collection_candidate"] == candidate
    assert manifest["provenance"]["source_config_override"] == {
        "path": str(source.resolve()), "sha256": release._file_hash(source),
    }

    wrong_source = official.fixture._audit(tmp_path, original)
    assert any(i["code"] == "COLLECTION_CONTRACT_INVALID" for i in wrong_source["issues"])

    pilot_id = old["pilots"][0]["run_id"]
    for run_id, filename in (
        (pilot_id, "collection-sources.yaml"),
        (pilot_id, "wazuh_archives.jsonl"),
        (challenge_id, "collection-sources.yaml"),
    ):
        path = tmp_path / "evidence/scenario-runs" / run_id / filename
        frozen_bytes = path.read_bytes()
        try:
            path.write_bytes(frozen_bytes + b"\n")
            corrupted = official.fixture._audit(tmp_path, source)
            assert corrupted["status"] == "NOT_READY"
            assert any(
                i.get("run_id") == run_id and i["severity"] == "ERROR"
                for i in corrupted["issues"]
            ), json.dumps(corrupted["issues"])
        finally:
            path.write_bytes(frozen_bytes)
