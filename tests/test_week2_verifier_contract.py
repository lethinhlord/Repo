"""The delivered shell verifier must accept the actual conservative API contract."""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.app.main import app

ROOT = Path(__file__).resolve().parents[1]


def test_shell_verifier_accepts_partial_legacy_fixture_without_claiming_complete(
    tmp_path, monkeypatch,
):
    client = TestClient(app)
    payload = json.loads((ROOT/'fixtures/wazuh-alert-account.json').read_text())
    response = client.post('/features/wazuh', json=payload)
    assert response.status_code == 200
    evidence = tmp_path/'evidence'
    evidence.mkdir()
    documents = {
        'week2-feature-response.json':response.json(),
        'week2-e2e-response.json':{'status':'review_notified', 'automation_state':'SHADOW',
            'strong_action_allowed':False, 'notification_status':'SENT', 'review_required':True},
        'week2-e2e-benign-response.json':{'status':'review_notified',
            'strong_action_allowed':False, 'review_required':True},
        'week2-e2e-degraded-response.json':{'response_code':401, 'status':'unauthorized',
            'automation_state':'SHADOW', 'strong_action_allowed':False, 'review_required':True},
    }
    for name, document in documents.items():
        (evidence/name).write_text(json.dumps(document), encoding='utf-8')
    source = (ROOT/'scripts/verify_week2.sh').read_text()
    check = source.split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
    monkeypatch.chdir(tmp_path)
    exec(compile(check, 'verify_week2_contract', 'exec'), {})
