"""Real fit on tiny invented data proves orchestration, not model quality."""

import json

import numpy as np
import pytest
from test_development_sources import development_data as development_data

from ml.training_sources import partition_bytes


def test_development_fit_records_day_folds_and_cannot_become_production(development_data):
    from ml.train_development import train

    root, manifest, rows, _, trainer, _ = development_data
    processed = root / "data/processed-development-v1"
    processed.mkdir(parents=True)
    (processed / "train.jsonl").write_bytes(partition_bytes(rows))
    (processed / "dataset_manifest.json").write_text(json.dumps(manifest))
    result = train(root=root, expected_commit=trainer)
    output = root / "ml/development-model-v1"
    metadata = json.loads((output / "metadata.json").read_bytes())
    metrics = json.loads((output / "metrics_development.json").read_bytes())
    assert metadata["deployment_eligible"] is metadata["automation_eligible"] is False
    assert (
        metadata["external_validation_status"] == metadata["locked_test_status"] == "NOT_COLLECTED"
    )
    assert result["status"] == "DEVELOPMENT_MODEL_TRAINED_REQUIRES_EXTERNAL_ASSESSMENT"
    import joblib

    bundle = joblib.load(output / "development_model.joblib")
    assert bundle["artifact_kind"] == "development-model-v1"
    for family, artifact in bundle["families"].items():
        m = metrics["families"][family]
        assert m["confidence_intervals"] is None
        assert m["uncertainty_status"] == "INSUFFICIENT_EXTERNAL_ASSESSMENT"
        assert len(m["nested_grouped_cv"]["folds"]) == 3
        for fold in m["nested_grouped_cv"]["folds"]:
            assert set(fold["fit_groups"]).isdisjoint(fold["assessment_groups"])
            assert len(fold["fit_groups"]) == 2 and len(fold["assessment_groups"]) == 1
        x = np.array(
            [
                [r["features"][k] for k in artifact["feature_order"]]
                for r in rows
                if r["family"] == family
            ]
        )
        assert np.isfinite(artifact["estimator"].predict_proba(x)).all()
    assert not (output / "metrics_validation.json").exists()
    from ml.inference import ModelPackageError, ModelRuntime

    with pytest.raises(ModelPackageError):
        ModelRuntime(output)
