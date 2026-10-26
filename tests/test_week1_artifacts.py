import json
from pathlib import Path

import yaml

from api.app.contracts import IncidentRequest

ROOT = Path(__file__).resolve().parents[1]


def test_wazuh_fixture_conforms_to_incident_contract() -> None:
    payload = json.loads((ROOT / "fixtures/wazuh-alert-account.json").read_text())
    normalized = payload["normalized_incident"]

    incident = IncidentRequest.model_validate(normalized)

    assert incident.incident_id == "WAZUH-W1-0001"
    assert incident.family_hint == "account"


def test_compose_pins_services_and_keeps_api_internal_to_n8n() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    services = compose["services"]

    assert services["n8n"]["image"] == (
        "docker.n8n.io/n8nio/n8n:2.44.6@sha256:"
        "d02752c6ab446ae9db8deec2f9cc887c378f77cdcad31650814df936b7386dfb"
    )
    assert services["api"]["image"] == "datn-ai-soar-api:week3"
    assert "build" not in services["api"]
    assert "${N8N_BIND_ADDRESS:-127.0.0.1}:5678:5678" in services["n8n"]["ports"]
    assert "127.0.0.1:8000:8000" in services["api"]["ports"]
    assert services["n8n"]["depends_on"]["api"]["condition"] == "service_healthy"


def test_n8n_workflow_has_the_week1_vertical_slice_and_no_strong_action() -> None:
    workflow = json.loads(
        (ROOT / "n8n/workflows/week1-wazuh-mock-ai.json").read_text()
    )
    nodes = {node["name"]: node for node in workflow["nodes"]}

    assert workflow["active"] is True
    assert set(nodes) == {
        "Wazuh Alert Webhook",
        "Normalize Wazuh Alert",
        "Call Mock AI API",
        "Build Shadow Notification",
    }
    assert nodes["Call Mock AI API"]["parameters"]["url"] == (
        "http://api:8000/orchestrate/mock"
    )
    serialized = json.dumps(workflow).lower()
    assert "isolate" not in serialized
    assert "block_ip" not in serialized
    assert "kill_process" not in serialized
    assert "shadow" in serialized
