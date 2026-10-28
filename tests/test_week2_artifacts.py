import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_schema_export_script_runs_without_pythonpath_override() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "export_week2_contracts.py")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def test_signed_webhook_script_runs_without_pythonpath_override() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "send_signed_webhook.py"), "--help"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Send a signed Wazuh webhook fixture" in result.stdout
    assert "--expect-http-status" in result.stdout


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
        "schemas/model-metrics.schema.json",
        "schemas/model-feedback-request.schema.json",
        "schemas/model-feedback-response.schema.json",
        "schemas/notification-dispatch-request.schema.json",
        "schemas/notification-dispatch-response.schema.json",
        "schemas/asset-context.schema.json",
        "schemas/ti-lookup.schema.json",
        "docs/week2-runbook.md",
        "docs/week2-acceptance-matrix.md",
        "docs/week2-security-notes.md",
        "scripts/verify_week2.sh",
        "scripts/generate_runtime_sbom.py",
        "scripts/verify_supply_chain.sh",
        "scripts/build_reproducible_image.sh",
        "scripts/verify_reproducible_image.sh",
        "scripts/bootstrap_ml.sh",
        "requirements-ml.lock",
        "requirements-runtime.lock",
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
        "Signature Headers Present?",
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
        "Dispatch Notification",
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
    assert nodes["Dispatch Notification"]["parameters"]["url"] == (
        "http://api:8000/notifications/dispatch"
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
    for node in nodes.values():
        if node["type"] != "n8n-nodes-base.httpRequest":
            continue
        url = node["parameters"]["url"]
        assert "http://api:8000/" in url
    connections = workflow["connections"]
    assert connections["Wazuh Alert Webhook v2"]["main"][0][0]["node"] == (
        "Signature Headers Present?"
    )
    header_outputs = connections["Signature Headers Present?"]["main"]
    assert header_outputs[0][0]["node"] == "Verify Signed Ingress"
    assert header_outputs[1][0]["node"] == "Build Unauthorized Response"
    decision_outputs = connections["Decision Ready?"]["main"]
    assert decision_outputs[0][0]["node"] == "Build Shadow Decision"
    assert decision_outputs[1][0]["node"] == "Build Review Decision"
    assert connections["Build Shadow Decision"]["main"][0][0]["node"] == (
        "Persist Incident And Queue"
    )
    assert connections["Build Review Decision"]["main"][0][0]["node"] == (
        "Persist Incident And Queue"
    )
    assert connections["Persist Incident And Queue"]["main"][0][0]["node"] == (
        "Select Recorded Outcome"
    )
    assert connections["Dispatch Notification"]["main"][0][0]["node"] == (
        "Finalize Response"
    )
    for name in (
        "Verify Signed Ingress",
        "Extract Incident Features",
        "Call AI Model",
        "Lookup Threat Intelligence",
        "Load Asset Context",
        "Evaluate Risk",
        "Persist Incident And Queue",
        "Dispatch Notification",
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

    assert "build" not in api
    assert api["ports"] == ["127.0.0.1:8000:8000"]
    assert api["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in api["security_opt"]
    assert api["environment"]["FEATURE_STATE_DB"] == "/app/state/feature-state.sqlite3"
    assert "feature_state:/app/state" in api["volumes"]
    assert compose["services"]["n8n"]["ports"] == [
        "${N8N_BIND_ADDRESS:-127.0.0.1}:5678:5678"
    ]
    assert compose["services"]["n8n"]["environment"]["N8N_PAYLOAD_SIZE_MAX"] == "2"
    assert compose["services"]["n8n"]["environment"]["N8N_UNVERIFIED_PACKAGES_ENABLED"] == (
        "false"
    )
    assert compose["services"]["n8n"]["environment"]["N8N_COMMUNITY_PACKAGES_ENABLED"] == (
        "false"
    )
    assert compose["services"]["n8n"]["environment"]["N8N_PUBLIC_API_DISABLED"] == (
        "true"
    )
    assert compose["services"]["n8n"]["environment"]["N8N_TEMPLATES_ENABLED"] == "false"
    assert "N8N_WEBHOOK_URL" in compose["services"]["n8n"]["environment"]
    assert "WEBHOOK_URL" not in compose["services"]["n8n"]["environment"]


def test_week3_ml_toolchain_is_selected_and_version_pinned() -> None:
    pins = (ROOT / "requirements-ml.lock").read_text(encoding="utf-8").splitlines()

    assert pins == ["scikit-learn==1.9.1", "xgboost-cpu==3.4.1"]


def test_runtime_dependencies_and_n8n_image_are_immutable() -> None:
    lock = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
    compose_text = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    assert "--hash=sha256:" in lock
    assert "docker.n8n.io/n8nio/n8n:2.44.6@sha256:" in compose_text
    assert "pip install --no-cache-dir --no-compile --only-binary=:all: --require-hashes" in (
        ROOT / "api" / "Dockerfile"
    ).read_text(encoding="utf-8")


def test_api_image_build_is_timestamp_normalized_and_bytecode_free() -> None:
    dockerfile = (ROOT / "api" / "Dockerfile").read_text(encoding="utf-8")
    builder = (ROOT / "scripts" / "build_reproducible_image.sh").read_text(
        encoding="utf-8"
    )
    deploy = (ROOT / "scripts" / "deploy_week2.sh").read_text(encoding="utf-8")
    legacy_deploy = (ROOT / "scripts" / "deploy_week1.sh").read_text(
        encoding="utf-8"
    )

    assert "--no-compile" in dockerfile
    assert "SOURCE_DATE_EPOCH" in builder
    assert "rewrite-timestamp=true" in builder
    assert "--provenance=false" in builder
    assert "--sbom=false" in builder
    assert "type=oci" in builder
    assert "docker load" in builder
    assert "build_reproducible_image.sh" in deploy
    assert "build_reproducible_image.sh" in legacy_deploy


def test_deployment_waits_for_functional_webhook_readiness() -> None:
    deploy = (ROOT / "scripts" / "deploy_week2.sh").read_text(encoding="utf-8")
    verify = (ROOT / "scripts" / "verify_week2.sh").read_text(encoding="utf-8")

    for script in (deploy, verify):
        assert "webhook/wazuh-alert-week2" in script
        assert 'webhook_status" = "401"' in script
