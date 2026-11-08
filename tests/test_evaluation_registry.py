import json
import shutil

import numpy as np
import pytest
from test_challenge_evaluation import fixture as challenge_fixture
from test_ml_audit_fixes import prepared_locked
from test_ml_package import SIGNING_KEY

from ml.evaluate import evaluate_locked_test
from ml.evaluate_challenge import evaluate_challenge
from ml.freeze_model import freeze
from ml.inference import ModelRuntime


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv("MODEL_PACKAGE_SIGNING_KEY", SIGNING_KEY)


@pytest.mark.parametrize("loss", ["namespace", "results", "ledger", "head"])
def test_consumed_locked_test_cannot_reset_after_evidence_loss(tmp_path, loss):
    package, locked = prepared_locked(tmp_path)
    evidence = tmp_path / "outputs"
    evaluate_locked_test(package, locked, unlock_locked_test=True, evidence_dir=evidence)
    runtime = ModelRuntime(package, evidence_dir=evidence)
    if loss == "namespace":
        shutil.rmtree(runtime.evidence_dir)
    elif loss == "results":
        for path in runtime.evidence_dir.iterdir():
            path.unlink()
    else:
        registry = package.parent / ".model-evaluation-registry"
        path = next(registry.glob("*.sqlite3" if loss == "ledger" else "*.head.json"))
        path.unlink()
    assert runtime.locked_test_status == "EVIDENCE_INTEGRITY_ERROR"
    with pytest.raises(
        (RuntimeError, ValueError, PermissionError), match="registry|ledger|integrity|already"
    ):
        evaluate_locked_test(package, locked, unlock_locked_test=True, evidence_dir=evidence)


def test_unopened_package_requires_existing_registry(tmp_path):
    package, locked = prepared_locked(tmp_path)
    registry = package.parent / ".model-evaluation-registry"
    shutil.rmtree(registry)
    with pytest.raises((RuntimeError, ValueError), match="registry|ledger"):
        ModelRuntime(package)
    with pytest.raises((RuntimeError, ValueError), match="registry|ledger"):
        freeze(package)
    assert not registry.exists()


def test_challenge_consumption_survives_output_deletion(tmp_path, monkeypatch):
    package, challenge, manifest, design = challenge_fixture(tmp_path, monkeypatch)
    freeze(package)
    evidence = tmp_path / "outputs"
    evaluate_challenge(package, challenge, manifest, design, evidence_dir=evidence)
    shutil.rmtree(evidence)
    with pytest.raises(
        (RuntimeError, ValueError, PermissionError), match="registry|ledger|integrity|already"
    ):
        evaluate_challenge(package, challenge, manifest, design, evidence_dir=evidence)


def test_outer_selection_ignores_outer_assessment_labels():
    from sklearn.linear_model import LogisticRegression
    from sklearn.tree import DecisionTreeClassifier

    from ml.training import grouped_calibrated_probabilities

    groups = np.repeat(np.arange(12), 4)
    y = np.repeat(np.arange(12) % 2, 4)
    x = np.column_stack([y * 3 + np.tile([-0.2, -0.1, 0.1, 0.2], 12), groups / 100])
    fitted = np.flatnonzero(groups < 8)
    heldout = np.flatnonzero(groups >= 8)
    candidates = {
        "linear": LogisticRegression(C=0.001),
        "tree": DecisionTreeClassifier(max_depth=1),
    }
    options = dict(outer_splits=[(fitted, heldout)], folds=3, method="sigmoid", random_seed=42)
    first, audit = grouped_calibrated_probabilities(candidates, x, y, groups, **options)
    changed = y.copy()
    changed[heldout] = 1 - changed[heldout]
    second, audit2 = grouped_calibrated_probabilities(candidates, x, changed, groups, **options)
    np.testing.assert_allclose(first[heldout], second[heldout])
    assert audit["folds"][0]["selected_model"] == audit2["folds"][0]["selected_model"]
    assert set(audit["folds"][0]["selection_groups"]) == set(groups[fitted])
    assert not set(audit["folds"][0]["selection_groups"]) & set(groups[heldout])


@pytest.mark.parametrize("fault", [None, "attestation", "receipt_hash", "bound_missing"])
def test_explicit_legacy_migration_requires_verified_archived_provenance(tmp_path, fault):
    from ml.evaluation_registry import migrate_legacy_registry, registry_paths
    from ml.freeze_model import sign_evidence

    package, _ = prepared_locked(tmp_path)
    frozen_path = package / "FROZEN.json"
    frozen = json.loads(frozen_path.read_text())
    if fault != "bound_missing":
        frozen.pop("evaluation_registry_id")
        frozen.pop("signature_hmac_sha256")
        frozen_path.write_text(json.dumps(sign_evidence(frozen)))
    archive = tmp_path / "archive"
    archive.mkdir()
    archived = archive / "original-freeze.json"
    archived.write_bytes(frozen_path.read_bytes())
    import hashlib

    digest = hashlib.sha256(archived.read_bytes()).hexdigest()
    receipt = sign_evidence(
        {
            "format_version": "evaluation-registry-migration-v1",
            "freeze_sha256": digest,
            "statuses": {"locked_test": "UNOPENED", "challenge": "UNOPENED"},
            "affirmative_unopened_attestation": fault != "attestation",
            "approved_by": "SYNTHETIC-ADMIN",
            "source_receipts": {
                "original-freeze.json": digest if fault != "receipt_hash" else "0" * 64
            },
        }
    )
    receipt_path = tmp_path / "migration.json"
    receipt_path.write_text(json.dumps(receipt))
    if fault:
        with pytest.raises(ValueError, match="migration|attestation|receipt|bound"):
            migrate_legacy_registry(package, receipt_path, archive)
    else:
        migrate_legacy_registry(package, receipt_path, archive)
        assert ModelRuntime(package).locked_test_status == "UNOPENED"
        with pytest.raises((ValueError, FileExistsError), match="already|exists"):
            migrate_legacy_registry(package, receipt_path, archive)
        ledger, _, _, _ = registry_paths(package)
        ledger.unlink()
        # A retained migration head prevents reinitialization even for legacy releases.
        with pytest.raises(ValueError, match="already|reinitialize"):
            migrate_legacy_registry(package, receipt_path, archive)


def test_ledger_rejects_tail_truncation_and_sql_updates(tmp_path):
    import sqlite3

    from ml.evaluation_registry import registry_paths, registry_status, transition

    package, _ = prepared_locked(tmp_path)
    transition(package, "locked_test", "RESERVED")
    ledger, _, _, _ = registry_paths(package)
    with sqlite3.connect(ledger) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append only"):
            connection.execute("DELETE FROM events WHERE sequence=1")
        # Simulate partial corruption bypassing the SQL guard; retained head detects it.
        connection.execute("DROP TRIGGER events_no_delete")
        connection.execute("DELETE FROM events WHERE sequence=1")
    with pytest.raises(ValueError, match="head disagree"):
        registry_status(package)


def test_challenge_interrupted_read_consumes_registry_before_input(tmp_path, monkeypatch):
    from pathlib import Path

    package, challenge, manifest, design = challenge_fixture(tmp_path, monkeypatch)
    freeze(package)
    evidence = tmp_path / "outputs"
    original = Path.read_bytes

    def interrupt(path):
        if path == challenge:
            raise OSError("synthetic interrupted challenge read")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", interrupt)
    with pytest.raises(OSError, match="interrupted challenge"):
        evaluate_challenge(package, challenge, manifest, design, evidence_dir=evidence)
    shutil.rmtree(evidence)
    with pytest.raises(PermissionError, match="already consumed"):
        evaluate_challenge(package, challenge, manifest, design, evidence_dir=evidence)


def test_migration_retains_complete_legacy_opening_provenance(tmp_path):
    import hashlib

    from ml.evaluation_registry import migrate_legacy_registry
    from ml.freeze_model import sign_evidence

    package, locked = prepared_locked(tmp_path)
    evaluate_locked_test(package, locked, unlock_locked_test=True)
    # Historical outputs were local to the package before external namespaces existed.
    previous_evidence = ModelRuntime(package).evidence_dir
    for path in previous_evidence.iterdir():
        (package / path.name).write_bytes(path.read_bytes())
    # Synthesize an internally consistent historical package without the new binding.
    frozen_path = package / "FROZEN.json"
    frozen = json.loads(frozen_path.read_text())
    frozen.pop("evaluation_registry_id")
    frozen.pop("signature_hmac_sha256")
    frozen_path.write_text(json.dumps(sign_evidence(frozen)))
    freeze_hash = hashlib.sha256(frozen_path.read_bytes()).hexdigest()
    opening = package / "LOCKED_TEST_OPENED.json"
    opened = json.loads(opening.read_text())
    opened.pop("signature_hmac_sha256")
    opened["freeze_sha256"] = freeze_hash
    opening.write_text(json.dumps(sign_evidence(opened)))
    names = ["LOCKED_TEST_RESERVED", "LOCKED_TEST_OPENED.json", "metrics_locked_test.json"]
    archive = tmp_path / "archive"
    archive.mkdir()
    sources = {}
    for name in ["FROZEN.json", *names]:
        archived = archive / name
        archived.write_bytes((package / name).read_bytes())
        sources[name] = hashlib.sha256(archived.read_bytes()).hexdigest()
    receipt = sign_evidence(
        {
            "format_version": "evaluation-registry-migration-v1",
            "freeze_sha256": freeze_hash,
            "statuses": {"locked_test": "CONSUMED", "challenge": "UNOPENED"},
            "affirmative_unopened_attestation": True,
            "approved_by": "SYNTHETIC-ADMIN",
            "source_receipts": sources,
            "evaluation_files_sha256": {"locked_test": {name: sources[name] for name in names}},
        }
    )
    receipt_path = tmp_path / "migration.json"
    receipt_path.write_text(json.dumps(receipt))
    migrate_legacy_registry(package, receipt_path, archive)
    assert ModelRuntime(package).locked_test_status == "EVALUATED"
    with pytest.raises(PermissionError, match="already"):
        evaluate_locked_test(package, locked, unlock_locked_test=True)


def test_bound_default_evaluation_preserves_immutable_package(tmp_path):
    package, locked = prepared_locked(tmp_path)
    original = {path.name: path.read_bytes() for path in package.iterdir()}
    evaluate_locked_test(package, locked, unlock_locked_test=True)
    runtime = ModelRuntime(package)
    assert runtime.evidence_dir != package
    assert runtime.evidence_dir.parent == package.parent / ".model-evaluation-evidence"
    assert original == {path.name: path.read_bytes() for path in package.iterdir()}
    assert runtime.locked_test_status == "EVALUATED"


def test_bound_default_challenge_preserves_immutable_package(tmp_path, monkeypatch):
    package, challenge, manifest, design = challenge_fixture(tmp_path, monkeypatch)
    freeze(package)
    original = {path.name: path.read_bytes() for path in package.iterdir()}
    evaluate_challenge(package, challenge, manifest, design)
    assert (
        ModelRuntime(package).evidence_dir.parent == package.parent / ".model-evaluation-evidence"
    )
    assert original == {path.name: path.read_bytes() for path in package.iterdir()}
