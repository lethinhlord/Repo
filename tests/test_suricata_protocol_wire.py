"""Real engine output generated from two harmless offline DNS packets."""
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import yaml

from ml.scenario_collection import SourceConfig, _validate_dns_profile_responses

ROOT = Path(__file__).resolve().parents[1]


def test_suricata807_wire_dns_id_not_engine_tx_id_correlates_response():
    rows = [
        json.loads(line) for line in
        (ROOT/"fixtures/protocol/suricata-8.0.7-dns.jsonl").read_text().splitlines()
    ]
    query, answer = [row for row in rows if row["event_type"] == "dns"]
    assert query["dns"]["tx_id"] != answer["dns"]["tx_id"]
    assert query["dns"]["id"] == answer["dns"]["id"]
    source = SourceConfig.model_validate(yaml.safe_load(
        (ROOT/"config/collection-sources.yaml").read_text()
    ))
    events = [{"agent": {"name": source.suricata_agent_name}, "full_log": json.dumps(row)}
              for row in rows]
    result = _validate_dns_profile_responses(
        events, [(query, datetime.fromisoformat(query["timestamp"]))],
        SimpleNamespace(scenario_parameters={"dns_server": "10.40.0.10"}), source,
    )
    assert len(result) == 1
    assert result[0][0] == answer
