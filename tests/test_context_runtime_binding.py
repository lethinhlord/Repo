"""Collector and container consume the same read-only baseline file by default."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_api_container_reads_the_collector_baseline_without_bundling_raw_evidence():
    api = yaml.safe_load((ROOT/'compose.yaml').read_text())['services']['api']
    source = yaml.safe_load((ROOT/'config/collection-sources.yaml').read_text())
    target = api['environment']['CONTEXT_BASELINE_PATH']
    bind = next(item for item in api['volumes'] if isinstance(item, dict)
                and item.get('target') == target)
    assert bind['source'] == '${CONTEXT_BASELINE_HOST_FILE:-./evidence/context-baseline.json}'
    assert source['context_baseline_path'] == 'evidence/context-baseline.json'
    assert bind['type'] == 'bind'
    assert bind['read_only'] is True
    assert bind['bind']['create_host_path'] is False
