import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_week2_required_artifacts_exist() -> None:
    expected = [
        "config/asset-context.yaml",
        "config/risk-policy-week2.yaml",
        "config/ti-policy.yaml",
        "fixtures/wazuh-alert-c2.json",
        "fixtures/wazuh-alert-account-benign.json",
        "fixtures/wazuh-alert-malformed.json",
        "ml/feature_schema.json",
        "n8n/workflows/week2-feature-ti-asset-shadow.json",
        "schemas/feature-pipeline-response.schema.json",
        "schemas/feature-state-response.schema.json",
        "schemas/incident-record-request.schema.json",
        "schemas/incident-record-response.schema.json",
        "schemas/signed-ingest-request.schema.json",
        "schemas/signed-ingest-response.schema.json",
        "schemas/asset-context.schema.json",
        "schemas/ti-lookup.schema.json",
        "docs/week2-runbook.md",
        "docs/week2-acceptance-matrix.md",
        "docs/week2-security-notes.md",
        "scripts/verify_week2.sh",
        "scripts/bootstrap_ml.sh",
        "requirements-ml.lock",
    ]

    assert all((ROOT / path).is_file() for path in expected)


def test_week2_n8n_workflow_is_complete_and_never_executes_strong_action() -> None:
    workflow = json.loads(
        (ROOT / "n8n/workflows/week2-feature-ti-asset-shadow.json").read_text(
            encoding="utf-8"
        )
    )
    nodes = {node["name"]: node for node in workflow["nodes"]}

    assert workflow["active"] is False
    required_nodes = {
        "Wazuh Alert Webhook v2",
        "Verify Signed Ingress",
        "Ingress Verified?",
        "Build Unauthorized Response",
        "Extract Incident Features",
        "Call AI Model",
        "Lookup Threat Intelligence",
        "Load Asset Context",
        "Evaluate Risk",
        "Enforce Shadow Gate",
        "Build Shadow Decision",
        "Build Review Decision",
        "Persist Incident And Queue",
        "Finalize Response",
        "Respond to Webhook",
    }
    assert required_nodes.issubset(nodes)
    assert nodes["Extract Incident Features"]["parameters"]["url"] == (
        "http://api:8000/features/wazuh/stateful"
    )
    assert nodes["Verify Signed Ingress"]["parameters"]["url"] == (
        "http://api:8000/ingress/wazuh/verify"
    )
    assert nodes["Call AI Model"]["parameters"]["url"] == "http://api:8000/predict"
    assert nodes["Lookup Threat Intelligence"]["parameters"]["url"] == (
        "http://api:8000/ti/lookup"
    )
    assert nodes["Evaluate Risk"]["parameters"]["url"] == (
        "http://api:8000/risk/evaluate"
    )
    assert nodes["Persist Incident And Queue"]["parameters"]["url"] == (
        "http://api:8000/incidents/record"
    )
    serialized = json.dumps(workflow).lower()
    assert "strong_action_allowed: false" in serialized
    assert "persist_incident_queue_review" in serialized
    assert "model_automation_eligible" in serialized
    assert "evidence_quality" in serialized
    assert "ti.status === 'malicious'" in serialized
    assert "x-apikey" not in serialized
    assert "vt_api_key" not in serialized
    for prohibited in ("isolate_host", "block_ip", "kill_process", "disable_user"):
        assert prohibited not in serialized
    connections = workflow["connections"]
    decision_outputs = connections["Decision Ready?"]["main"]
    assert decision_outputs[0][0]["node"] == "Build Shadow Decision"
    assert decision_outputs[1][0]["node"] == "Build Review Decision"
    assert connections["Build Shadow Decision"]["main"][0][0]["node"] == (
        "Persist Incident And Queue"
    )
    assert connections["Build Review Decision"]["main"][0][0]["node"] == (
        "Persist Incident And Queue"
    )
    for name in (
        "Verify Signed Ingress",
        "Extract Incident Features",
        "Call AI Model",
        "Lookup Threat Intelligence",
        "Load Asset Context",
        "Evaluate Risk",
        "Persist Incident And Queue",
    ):
        assert nodes[name]["onError"] == "continueRegularOutput"


def test_week2_risk_policy_keeps_frozen_weights_and_shadow_gate() -> None:
    policy = yaml.safe_load(
        (ROOT / "config/risk-policy-week2.yaml").read_text(encoding="utf-8")
    )

    assert policy["revision"] == "risk-week2-v2"
    assert policy["weights"] == {
        "ai": 0.40,
        "observed_evidence": 0.20,
        "threat_intelligence": 0.15,
        "asset": 0.15,
        "severity": 0.10,
    }
    assert sum(policy["weights"].values()) == 1.0
    assert policy["automation_state"] == "SHADOW"
    assert policy["strong_actions_enabled"] is False
    assert policy["missing_signal_strategy"] == "zero_contribution_review"
    assert policy["allowed_playbooks"] == ["persist_incident_queue_review"]


def test_environment_template_defaults_to_offline_reproducible_ti() -> None:
    env_template = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "VT_MODE=mock" in env_template
    assert "VT_API_KEY=" in env_template
    assert "VT_TIMEOUT_SECONDS=5" in env_template


def test_compose_limits_api_host_exposure_and_drops_capabilities() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    api = compose["services"]["api"]

    assert api["ports"] == ["127.0.0.1:8000:8000"]
    assert api["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in api["security_opt"]
    assert api["environment"]["FEATURE_STATE_DB"] == "/app/state/feature-state.sqlite3"
    assert "feature_state:/app/state" in api["volumes"]
    assert compose["services"]["n8n"]["ports"] == [
        "${N8N_BIND_ADDRESS:-127.0.0.1}:5678:5678"
    ]
    assert compose["services"]["n8n"]["environment"]["N8N_PAYLOAD_SIZE_MAX"] == "2"


def test_week3_ml_toolchain_is_selected_and_version_pinned() -> None:
    pins = (ROOT / "requirements-ml.lock").read_text(encoding="utf-8").splitlines()

    assert pins == ["scikit-learn==1.9.1", "xgboost==3.4.1"]
