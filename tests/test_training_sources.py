"""Reviewed origins require pinned source, immutable inputs and a fixed split."""
import json
import subprocess

import pytest

from ml import training_sources as sources


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def commit(root):
    git(root, 'add', '.')
    git(root, '-c', 'user.name=Unit', '-c', 'user.email=unit@example.invalid',
        'commit', '-qm', 'unit snapshot')
    return git(root, 'rev-parse', 'HEAD')


@pytest.fixture
def reviewed(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    root.mkdir()
    git(root, 'init', '-q')
    git(root, 'remote', 'add', 'origin', 'https://github.com/lethinhlord/Repo.git')
    (root / 'module.py').write_text('version = 1\n')
    (root / 'config').mkdir()
    (root / 'ml').mkdir()
    (root / 'config/collection-design.yaml').write_text('version: unit\n')
    (root / 'ml/feature_schema.json').write_text('{}\n')
    (root / 'ml/training_config.yaml').write_text('version: unit\n')
    old = commit(root)
    (root / 'module.py').write_text('version = 2\n')
    new = commit(root)
    raw = tmp_path / 'dataset/data/raw'
    evidence = tmp_path / 'dataset/evidence/scenario-runs'
    origins = {}
    for sha in (old, new):
        origins[sha] = {'candidate': {'commit': sha, 'tag': 'unit-' + sha[:8],
            'version': 'collection-candidate-v1', 'origin': 'https://github.com/lethinhlord/Repo.git',
            'tag_object': 'a' * 40, 'tracked_files_sha256': sources.source_tree_hash(root, sha),
            'python_version': 'unit', 'node_version': 'unit',
            'installed_packages_sha256': 'b' * 64},
            'acceptance_sha256': 'c' * 64}
    policy = {'version': sources.POLICY_VERSION, 'processing_sha256': sources.processing_hash(root),
              'origins': origins, 'approved_runs': {}, 'partitions': {},
              'processing_runtimes': [{'python_version': 'unit',
                                      'installed_packages_sha256': 'b' * 64}]}
    monkeypatch.setattr(sources, 'runtime_identity', lambda: policy['processing_runtimes'][0])
    rows, ids = [], []
    for index, partition in enumerate(('train', 'validation', 'locked_test')):
        rid = f'UNIT-REVIEWED-{index}'
        ids.append(rid)
        (raw / rid).mkdir(parents=True)
        (evidence / rid).mkdir(parents=True)
        origin = old if index < 2 else new
        row = {'run_id': rid, 'incident_id': rid + '-incident', 'scenario_id': rid + '-scenario',
               'cohort_id': rid + '-cohort', 'family': 'account', 'label': index % 2,
               'purpose': 'trainable', 'features': {'failed_login_count': float(index)},
               'source_file': '/private/machine/input.jsonl'}
        state = {'collection_candidate': origins[origin]['candidate'],
                 'collection_candidate_sha256': sources.digest(origins[origin]['candidate']),
                 'collection_release': {'record_sha256': 'c' * 64},
                 'collection_contract_sha256': 'd' * 64}
        (evidence / rid / '.collection_state.json').write_text(json.dumps(state))
        (raw / rid / 'incidents.jsonl').write_text(json.dumps(row) + '\n')
        (raw / rid / 'scenario_manifest.json').write_text('{}')
        key = sources.run_key(rid)
        policy['approved_runs'][key] = {'origin_commit': origin,
            'input_sha256': sources.run_input_hash(raw, evidence, rid),
            'record_sha256': sources.digest(sources.canonical_record(row))}
        rows.append(row)
        policy['partitions'][partition] = sources.partition_commitment([row])
    policy['dataset_hash_sha256'] = sources.canonical_dataset_hash(rows)
    policy['collection_contract_sha256'] = 'd' * 64
    policy['split_assignment_commitment_sha256'] = 'e' * 64
    import hashlib
    policy['feature_schema_sha256'] = hashlib.sha256(
        (root / 'ml/feature_schema.json').read_bytes()).hexdigest()
    policy['collection_design_sha256'] = hashlib.sha256(
        (root / 'config/collection-design.yaml').read_bytes()).hexdigest()
    policy['builder_config_sha256'] = hashlib.sha256(
        (root / 'ml/training_config.yaml').read_bytes()).hexdigest()
    p = root / sources.POLICY_RELATIVE
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps(policy, sort_keys=True))
    commit(root)
    calls = []
    monkeypatch.setattr('scripts.verify_run_evidence.verify_run_evidence',
                        lambda rid, _: calls.append(rid) or {'status': 'RUN_EVIDENCE_CHECK_PASS'})
    monkeypatch.setattr('ml.collection_release.verify_frozen_acceptance', lambda _: None)
    return root, raw, evidence, ids, rows, policy, calls


def test_reviewed_two_origins_preserve_identity_and_replay_every_run(reviewed):
    root, raw, evidence, ids, _, policy, calls = reviewed
    cert = sources.verify_training_sources(root, raw, evidence, ids, root / sources.POLICY_RELATIVE)
    assert set(calls) == set(ids)
    assert cert['runs'] == policy['approved_runs']
    assert len(cert['origins']) == 2
    assert cert['processing_commit'] == git(root, 'rev-parse', 'HEAD')


@pytest.mark.parametrize('mutation', ['raw', 'source', 'policy', 'third_origin', 'subset'])
def test_reviewed_mode_rejects_mutations_and_incomplete_inventory(reviewed, mutation):
    root, raw, evidence, ids, _, _, _ = reviewed
    if mutation == 'raw':
        (raw / ids[0] / 'incidents.jsonl').write_text('{}\n')
    elif mutation == 'source':
        (root / 'module.py').write_text('changed = True\n')
    elif mutation == 'policy':
        (root / sources.POLICY_RELATIVE).write_text('{}')
    elif mutation == 'third_origin':
        p = evidence / ids[0] / '.collection_state.json'
        s = json.loads(p.read_text())
        s['collection_candidate']['commit'] = 'f' * 40
        p.write_text(json.dumps(s))
    else:
        ids = ids[:-1]
    with pytest.raises(ValueError):
        sources.verify_training_sources(root, raw, evidence, ids, root / sources.POLICY_RELATIVE)


def test_v3_rejects_record_and_partition_forgery_without_reading_locked(reviewed):
    root, raw, evidence, ids, rows, policy, _ = reviewed
    cert = sources.verify_training_sources(root, raw, evidence, ids, root / sources.POLICY_RELATIVE)
    manifest = {'manifest_version': 'dataset-manifest-v3',
        'provenance': {'builder_git_commit': git(root, 'rev-parse', 'HEAD'),
                       'source_compatibility_sha256': sources.digest(cert),
                       'collection_contract_sha256': policy['collection_contract_sha256'],
                       'collection_design_sha256': policy['collection_design_sha256'],
                       'builder_config_sha256': policy['builder_config_sha256'],
                       'collection_mode': 'REAL_LAB'},
        'collection_audit': {'source_compatibility': cert,
                            'status': 'READY',
                            'collection_contract_sha256': policy['collection_contract_sha256'],
                            'collection_design_sha256': policy['collection_design_sha256']},
        'feature_schema_sha256': policy['feature_schema_sha256'],
        'group_key': 'cohort_id', 'locked_test_status': 'UNOPENED',
        'partition_counts': {n: 1 for n in sources.PARTITIONS},
        'record_counts': {n: 1 for n in sources.PARTITIONS},
        'split_assignment_commitment_sha256': policy['split_assignment_commitment_sha256'],
        'dataset_hash_sha256': policy['dataset_hash_sha256'],
        'locked_test_sha256': policy['partitions']['locked_test']['sha256'],
        'source_partitions': policy['partitions'],
        'partitions': {k: {'sha256': v['sha256'], 'record_count': v['record_count']}
                       for k, v in policy['partitions'].items()}}
    partitions = {'train': [sources.canonical_record(rows[0])],
                  'validation': [sources.canonical_record(rows[1])]}
    sources.verify_training_manifest(manifest, partitions, root=root)
    partitions['train'][0]['features']['failed_login_count'] = 999
    with pytest.raises(ValueError):
        sources.verify_training_manifest(manifest, partitions, root=root)


def test_reviewed_run_cannot_downgrade_to_v2(reviewed):
    root, _, _, _, rows, _, _ = reviewed
    with pytest.raises(ValueError, match='v3'):
        sources.verify_training_manifest({'manifest_version': 'dataset-manifest-v2'},
                                        {'train': [rows[0]], 'validation': []}, root=root)
    sources.verify_training_manifest({'manifest_version': 'dataset-manifest-v2'},
                                    {'train': [{'run_id': 'UNRELATED-LEGACY'}]}, root=root)
