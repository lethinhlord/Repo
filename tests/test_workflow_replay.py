import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    document = json.loads((ROOT / "n8n/workflows/week2-feature-ti-asset-shadow.json").read_text())
    return document, {node["name"]: node for node in document["nodes"]}


def test_verified_replay_bypasses_feature_model_and_ti_nodes() -> None:
    document, nodes = workflow()
    connections = document["connections"]
    assert connections["Ingress Verified?"]["main"][0][0]["node"] == "Find Persisted Outcome"
    assert "payload_sha256" in nodes["Find Persisted Outcome"]["parameters"]["url"]
    assert connections["Persisted Outcome?"]["main"][0][0]["node"] == "Use Persisted Outcome"
    assert connections["Use Persisted Outcome"]["main"][0][0]["node"] == "Select Recorded Outcome"
    assert connections["Select Recorded Outcome"]["main"][0][0]["node"] == "Dispatch Notification"
    assert connections["Outcome Missing?"]["main"][0][0]["node"] == "Extract Incident Features"
    assert connections["Outcome Missing?"]["main"][1][0]["node"] == "Build Outcome Lookup Failure"


def test_outcome_retries_dispatch_the_original_revision_and_preserve_raw_hash() -> None:
    _, nodes = workflow()
    dispatch = nodes["Dispatch Notification"]["parameters"]["body"]
    assert "notification_revision" in dispatch
    for name in ("Build Shadow Decision", "Build Review Decision"):
        assert "source_payload_sha256" in nodes[name]["parameters"]["jsCode"]
    final = nodes["Finalize Response"]["parameters"]["jsCode"]
    assert 'Select Recorded Outcome' in final
    assert "decision_superseded" in final
    assert "superseded_by_revision" in final
