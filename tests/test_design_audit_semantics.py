from pathlib import Path

import pytest
import yaml

from ml.collection_design import load_collection_design, separation_severity

ROOT = Path(__file__).resolve().parents[1]


def test_observable_target_separation_diagnostic_but_nuisance_always_blocks():
    design = load_collection_design(ROOT / "config/scenario-catalog.yaml")
    assert design
    assert separation_severity(design, "account", {"failed_login_count"}) == "WARNING"
    assert separation_severity(design, "account", {"remote_logon_ratio"}) == "ERROR"
    assert (
        separation_severity(design, "account", {"remote_logon_ratio", "new_source_for_user"})
        == "ERROR"
    )
    assert (
        separation_severity(design, "account", {"failed_login_count", "successful_login_count"})
        == "WARNING"
    )
    assert (
        separation_severity(design, "c2", {"suspicious_process", "destination_port_count"})
        == "ERROR"
    )
    assert separation_severity(None, "account", {"failed_login_count"}) == "ERROR"


def test_design_cannot_reclassify_shortcuts_or_remove_collision_gate(tmp_path):
    original = yaml.safe_load((ROOT / "config/collection-design.yaml").read_text())
    path = tmp_path / "collection-design.yaml"
    original["audit_policy"]["nuisance_features"]["c2"].remove("suspicious_process")
    path.write_text(yaml.safe_dump(original))
    with pytest.raises(ValueError, match="semantic roles"):
        load_collection_design(tmp_path / "catalog.yaml")
