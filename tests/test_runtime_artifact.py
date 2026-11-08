import copy

import pytest

from scripts.verify_runtime_artifact import source_inventory, verify_snapshots


def test_runtime_qa_and_checkout_must_agree_without_dependency_drift():
    source = {"api/app.py": "a"*64, "ml/model.py": "b"*64}
    base = {"sources": source, "packages": {"runtime-lib": "1.0"}}
    qa = {"sources": source, "packages": {"runtime-lib": "1.0", "pytest": "9.1.1"}}
    verify_snapshots(source, base, qa)
    for fault in ("source", "extra_source", "qa_source", "runtime_dependency", "optional_runtime"):
        damaged_base, damaged_qa = copy.deepcopy(base), copy.deepcopy(qa)
        if fault == "source":
            damaged_base["sources"]["ml/model.py"] = "c"*64
        elif fault == "extra_source":
            damaged_base["sources"]["api/unexpected.py"] = "d"*64
        elif fault == "qa_source":
            damaged_qa["sources"]["api/app.py"] = "e"*64
        elif fault == "runtime_dependency":
            damaged_qa["packages"]["runtime-lib"] = "2.0"
        else:
            damaged_qa["packages"]["uvloop"] = "0.22.0"
        with pytest.raises(ValueError):
            verify_snapshots(source, damaged_base, damaged_qa)


def test_source_snapshot_excludes_only_explicit_nonimage_runtime_state(tmp_path):
    for name in ("api/app.py", "ml/model.py", "config/policy.yaml",
                 "ml/.model-evaluation-registry/private.sqlite3", "ml/model-package/model.joblib",
                 "ml/.model-evaluation-evidence/result.json", "ml/splits/locked_test.txt"):
        path = tmp_path/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
    assert set(source_inventory(tmp_path)) == {"api/app.py", "ml/model.py", "config/policy.yaml"}
