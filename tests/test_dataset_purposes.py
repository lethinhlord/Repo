"""Training purpose and shared behavior cohorts are not classifier inputs."""
from pathlib import Path

import pytest

from ml.dataset import DatasetError, DatasetRecord, assign_grouped_folds, discover_records
from scripts.generate_smoke_dataset import generate


def test_matched_cohort_keeps_both_labels_in_the_same_fold() -> None:
    rows = [DatasetRecord(
        incident_id=f'{family}-{cohort}-{label}-{repeat}',
        scenario_id=f'{family}-{label}-S{cohort}',
        run_id=f'{family}-{cohort}-{label}-{repeat}', family=family, label=label,
        features={}, source_file='unit-only', cohort_id=f'{family}-PAIR-{cohort}',
    ) for family in ('account','c2') for cohort in range(5)
      for label in (0,1) for repeat in range(2)]
    folds = assign_grouped_folds(rows, number_of_folds=5, random_seed=42, group_key='cohort_id')
    assert folds == assign_grouped_folds(
        rows, number_of_folds=5, random_seed=42, group_key='cohort_id',
    )
    for row in rows:
        peers = [x for x in rows if x.cohort_id == row.cohort_id]
        assert len({folds[x.run_id] for x in peers}) == 1
    for fold in range(5):
        assert {(x.family,x.label) for x in rows if folds[x.run_id] == fold} == {
            ('account',0),('account',1),('c2',0),('c2',1),
        }


def test_cohort_split_rejects_missing_explicit_cohort() -> None:
    rows = [DatasetRecord(
        incident_id=str(i), scenario_id=str(i),run_id=str(i),family='account',label=i%2,
        features={},source_file='unit-only',
    ) for i in range(10)]
    with pytest.raises(DatasetError,match='cohort'):
        assign_grouped_folds(rows,number_of_folds=5,random_seed=42,group_key='cohort_id')


def test_discovery_excludes_challenge_and_pilot_from_training(tmp_path: Path) -> None:
    import json
    generate(tmp_path/'data/raw')
    manifests = sorted((tmp_path/'data/raw').glob('*/scenario_manifest.json'))
    original = discover_records(tmp_path/'data/raw','scenario_manifest.json','incidents.jsonl')
    excluded = set()
    for path,purpose in zip(manifests[:2],('challenge','pilot'),strict=True):
        payload = json.loads(path.read_text())
        payload['purpose'] = purpose
        excluded.add(payload['run_id'])
        path.write_text(json.dumps(payload),encoding='utf-8')
    training = discover_records(tmp_path/'data/raw','scenario_manifest.json','incidents.jsonl')
    assert not excluded & {x.run_id for x in training}
    assert len(training) < len(original)
    challenge = discover_records(
        tmp_path/'data/raw','scenario_manifest.json','incidents.jsonl',
        include_purposes=('challenge',),
    )
    assert challenge and {x.purpose for x in challenge} == {'challenge'}
    assert set(challenge[0].features).isdisjoint({'purpose','label','cohort_id'})


def test_record_metadata_does_not_leak_into_feature_vector() -> None:
    row = DatasetRecord(
        incident_id='I',scenario_id='S',run_id='R',family='account',label=1,
        features={'failed_login_count':1.0},source_file='unit-only',
        purpose='challenge',cohort_id='PAIR',
    )
    assert row.as_dict()['purpose'] == 'challenge'
    assert row.as_dict()['cohort_id'] == 'PAIR'
    assert row.as_dict()['features'] == {'failed_login_count':1.0}


def test_training_audit_rejects_shared_cohort_with_different_scenarios() -> None:
    from ml.training import leakage_audit
    def row(run, scenario):
        return DatasetRecord(
            incident_id=run, scenario_id=scenario, run_id=run, family='account', label=0,
            features={}, source_file='unit-only', cohort_id='MATCHED-PAIR',
        ).as_dict()
    result = leakage_audit([row('train','benign')], [row('validation','malicious')])
    assert result['passed'] is False
    assert result['checks']['cohort_overlap'] == ['MATCHED-PAIR']


def test_trainer_cv_uses_cohort_instead_of_separating_its_labels() -> None:
    from ml.training import _matrix
    rows = [DatasetRecord(
        incident_id=f'I{label}', scenario_id=f'S{label}', run_id=f'R{label}', family='account',
        label=label, features={'value':float(label)}, source_file='unit-only', cohort_id='PAIR',
    ).as_dict() for label in (0,1)]
    assert _matrix(rows, 'account', ['value'])[2].tolist() == ['PAIR','PAIR']


def test_repeated_scenario_cannot_be_renamed_into_separate_cohorts() -> None:
    rows = [DatasetRecord(
        incident_id=f'I-{family}-{label}-{cohort}', scenario_id=f'S-{family}-{label}',
        run_id=f'R-{family}-{label}-{cohort}', family=family, label=label, features={},
        source_file='unit-only', cohort_id=f'{family}-COHORT-{cohort}',
    ) for family in ('account','c2') for label in (0,1) for cohort in range(5)]
    with pytest.raises(DatasetError, match='scenario.*cohort'):
        assign_grouped_folds(rows, number_of_folds=5, random_seed=42, group_key='cohort_id')
