"""Fresh synthetic fixtures only test partition plumbing, never model effectiveness."""
import hashlib
import json
import shutil
from pathlib import Path

import yaml

from ml.build_dataset import build_dataset
from ml.training import verify_training_partitions
from scripts.generate_smoke_dataset import generate

ROOT = Path(__file__).resolve().parents[1]


def test_builder_commits_challenge_separately_and_keeps_shared_cohorts_together(tmp_path):
    raw = tmp_path/'raw'
    generate(raw)
    for path in raw.glob('*/scenario_manifest.json'):
        manifest = json.loads(path.read_text())
        slot = manifest['scenario_id'].rsplit('-',1)[1]
        manifest['cohort_id'] = f"{manifest['family']}-PAIR-{slot}"
        path.write_text(json.dumps(manifest), encoding='utf-8')
    original = next(raw.iterdir())
    challenge = raw/'CHALLENGE-ONLY-UNIT'
    shutil.copytree(original, challenge)
    path = challenge/'scenario_manifest.json'
    manifest = json.loads(path.read_text())
    manifest.update(run_id=challenge.name, scenario_id='CHALLENGE-UNIT', purpose='challenge',
                    cohort_id='CHALLENGE-PAIR-UNIT')
    path.write_text(json.dumps(manifest), encoding='utf-8')
    rows = [json.loads(line) for line in (challenge/'incidents.jsonl').read_text().splitlines()]
    for index, row in enumerate(rows):
        row['incident']['incident_id'] = f'CHALLENGE-INCIDENT-{index}'
    (challenge/'incidents.jsonl').write_text(
        ''.join(json.dumps(row)+'\n' for row in rows), encoding='utf-8',
    )
    config = yaml.safe_load((ROOT/'config/training-smoke.yaml').read_text())
    config['feature_schema'] = str(ROOT/'ml/feature_schema.json')
    config['data'].update(raw_dir=str(raw), processed_dir=str(tmp_path/'processed'),
        splits_dir=str(tmp_path/'splits'), group_key='cohort_id')
    config_path = tmp_path/'config.yaml'
    config_path.write_text(yaml.safe_dump(config), encoding='utf-8')
    result = build_dataset(config_path)
    assert result['group_key'] == 'cohort_id'
    assert result['challenge']['record_count'] == 4
    assert result['challenge']['training_eligible'] is False
    assert result['challenge']['sha256'] == hashlib.sha256(
        (tmp_path/'processed/challenge.jsonl').read_bytes(),
    ).hexdigest()
    partitions = {}
    for name in ('train','validation','locked_test'):
        lines = (tmp_path/f'processed/{name}.jsonl').read_text().splitlines()
        output = [json.loads(line) for line in lines]
        assert all(row['purpose'] == 'trainable' for row in output)
        assert not any(row['run_id'] == challenge.name for row in output)
        partitions[name] = {row['cohort_id'] for row in output}
    assert not partitions['train'] & partitions['validation']
    assert not partitions['train'] & partitions['locked_test']
    assert not partitions['validation'] & partitions['locked_test']
    # Trainer verification must succeed without opening or even retaining locked test.
    (tmp_path/'processed/locked_test.jsonl').unlink()
    train, validation, checked = verify_training_partitions(
        tmp_path/'processed', ROOT/'ml/feature_schema.json', require_collection_audit=False,
    )
    assert train and validation and checked['locked_test_status'] == 'UNOPENED'
