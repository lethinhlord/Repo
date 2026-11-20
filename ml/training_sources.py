"""Reviewed training origins; metadata verification uses the standard library only.

Original collection identities never become the processing identity. A tracked
policy authorizes exact input and output commitments, not arbitrary mixed data.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

POLICY_RELATIVE = 'config/training-source-compatibility.json'
POLICY_VERSION = 'reviewed-training-origins-v1'
CERTIFICATE_VERSION = 'training-source-compatibility-v1'
ROOT = Path(__file__).resolve().parents[1]
PARTITIONS = ('train', 'validation', 'locked_test')


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
    ).encode('utf-8')).hexdigest()


def run_key(run_id: str) -> str:
    return hashlib.sha256(run_id.encode('utf-8')).hexdigest()


def runtime_identity() -> dict[str, str]:
    packages = subprocess.check_output(
        [sys.executable, '-m', 'pip', 'freeze', '--all'], text=True, timeout=30,
    ).splitlines()
    return {'python_version': sys.version, 'installed_packages_sha256': digest(sorted(packages))}


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ['git', '-C', str(root), *args], text=True, stderr=subprocess.PIPE, timeout=30,
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(
            'cannot verify processing Git provenance; fetch the pinned history',
        ) from exc


def _files(root: Path, commit: str) -> dict[str, bytes]:
    from ml.collection_adoption import _archive_files

    return _archive_files(root, commit)


def source_tree_hash(root: Path, commit: str) -> str:
    return digest({n: hashlib.sha256(b).hexdigest() for n, b in _files(root, commit).items()})


def processing_hash(root: Path, commit: str = 'HEAD') -> str:
    # Both review documents are separately Git-pinned. Excluding them avoids
    # circular hashes between source and the two review-policy commitments.
    return digest({n: hashlib.sha256(b).hexdigest() for n, b in _files(root, commit).items()
                   if n not in {POLICY_RELATIVE, 'config/collection-pilot-adoption.json'}
                   and not n.startswith(('docs/', 'tests/', 'tasks/'))})


def canonical_record(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result['source_file'] = f"data/raw/{row['run_id']}/incidents.jsonl"
    return result


def partition_bytes(rows: list[dict[str, Any]]) -> bytes:
    return ''.join(json.dumps(canonical_record(row), sort_keys=True) + '\n'
                   for row in rows).encode('utf-8')


def partition_commitment(rows: list[dict[str, Any]]) -> dict[str, Any]:
    keys = [run_key(row['run_id']) for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError('reviewed partitions require exactly one record per run')
    return {'sha256': hashlib.sha256(partition_bytes(rows)).hexdigest(),
            'record_count': len(rows), 'run_keys_sha256': digest(sorted(keys))}


def canonical_dataset_hash(rows: list[dict[str, Any]]) -> str:
    raw = ''.join(json.dumps(canonical_record(row), sort_keys=True, separators=(',', ':')) + '\n'
                  for row in sorted(rows, key=lambda r: (r['run_id'], r['incident_id'])))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def run_input_hash(raw_dir: Path, evidence_dir: Path, run_id: str) -> str:
    files = {}
    for label, directory in (('raw', raw_dir / run_id), ('evidence', evidence_dir / run_id)):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('missing or linked reviewed run directory')
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValueError('reviewed run has an unsupported input member')
            files[f'{label}/{path.name}'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest(files)


def _policy(root: Path, policy_path: Path | None = None) -> tuple[dict, str, str]:
    root = root.resolve()
    expected = root / POLICY_RELATIVE
    selected = Path(policy_path) if policy_path is not None else expected
    if not selected.is_absolute():
        selected = root / selected
    if selected.is_symlink() or selected.resolve() != expected.resolve():
        raise ValueError('training compatibility policy must be the pinned source policy')
    commit = _git(root, 'rev-parse', 'HEAD')
    raw = selected.read_bytes()
    committed_files = _files(root, commit)
    if raw != committed_files.get(POLICY_RELATIVE):
        raise ValueError('reviewed training policy differs from committed source')
    if _git(root, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('processing source is dirty; commit reviewed code before building')
    for name, committed in committed_files.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('missing or linked processing source file')
        actual = path.read_bytes()
        if actual != committed:
            # Match Git's declared LF checkout semantics on Windows, without
            # allowing smudge filters or assume-unchanged to hide code changes.
            try:
                equivalent = actual.decode('utf-8').replace('\r\n', '\n').encode('utf-8')
            except UnicodeDecodeError:
                equivalent = actual
            if equivalent != committed:
                raise ValueError('executing processing bytes differ from reviewed Git source')
    policy = json.loads(raw)
    if (not isinstance(policy, dict) or policy.get('version') != POLICY_VERSION
            or policy.get('processing_sha256') != processing_hash(root, commit)
            or not isinstance(policy.get('origins'), dict) or len(policy['origins']) < 2
            or not isinstance(policy.get('approved_runs'), dict) or not policy['approved_runs']
            or not isinstance(policy.get('processing_runtimes'), list)
            or not policy['processing_runtimes']
            or set(policy.get('partitions', {})) != set(PARTITIONS)):
        raise ValueError('invalid reviewed training source/processing contract')
    for field, name in (('feature_schema_sha256', 'ml/feature_schema.json'),
                        ('collection_design_sha256', 'config/collection-design.yaml'),
                        ('builder_config_sha256', 'ml/training_config.yaml')):
        if policy.get(field) != hashlib.sha256(committed_files[name]).hexdigest():
            raise ValueError('processing schema/design differs from reviewed policy')
    return policy, hashlib.sha256(raw).hexdigest(), commit


def _certificate(policy: dict, policy_sha: str, commit: str, runtime: dict) -> dict:
    if runtime not in policy['processing_runtimes']:
        raise ValueError('processing runtime is outside the reviewed inventory')
    return {'version': CERTIFICATE_VERSION, 'policy_sha256': policy_sha,
            'processing_sha256': policy['processing_sha256'], 'processing_commit': commit,
            'processing_runtime': runtime,
            'collection_contract_sha256': policy['collection_contract_sha256'],
            'origins': policy['origins'], 'runs': policy['approved_runs'],
            'partitions': policy['partitions'],
            'dataset_hash_sha256': policy['dataset_hash_sha256'],
            'design_semantics_sha256': policy.get('design_semantics_sha256'),
            'builder_config_sha256': policy['builder_config_sha256']}


def verify_training_sources(
    root: Path, raw_dir: Path, evidence_dir: Path, run_ids: list[str], policy_path: Path,
) -> dict:
    """Require reviewed original bytes and real collector replay for every run."""
    from ml.collection_release import verify_frozen_acceptance
    from scripts.verify_run_evidence import verify_run_evidence

    policy, policy_sha, commit = _policy(root, policy_path)
    project = evidence_dir.resolve().parents[1]
    if (raw_dir.resolve() != (project / 'data/raw').resolve()
            or evidence_dir.resolve() != (project / 'evidence/scenario-runs').resolve()):
        raise ValueError('hashed inputs must be the same raw/evidence paths used by replay')
    keys = [run_key(rid) for rid in run_ids]
    if len(set(keys)) != len(keys) or set(keys) != set(policy['approved_runs']):
        raise ValueError('reviewed run inventory is incomplete or contains an unapproved run')
    for sha, origin in policy['origins'].items():
        candidate = origin['candidate']
        if (sha != candidate['commit']
                or source_tree_hash(root, sha) != candidate['tracked_files_sha256']):
            raise ValueError('original collection source tree is unavailable or inconsistent')
        _git(root, 'merge-base', '--is-ancestor', sha, commit)
    for rid in sorted(run_ids):
        approved = policy['approved_runs'][run_key(rid)]
        if run_input_hash(raw_dir, evidence_dir, rid) != approved['input_sha256']:
            raise ValueError(f'reviewed raw/evidence inventory changed: {rid}')
        state = json.loads((evidence_dir / rid / '.collection_state.json').read_bytes())
        origin = policy['origins'][approved['origin_commit']]
        if (state.get('collection_candidate') != origin['candidate']
                or state.get('collection_candidate_sha256') != digest(origin['candidate'])
                or state.get('collection_release', {}).get('record_sha256')
                != origin['acceptance_sha256']
                or state.get('collection_contract_sha256') != policy['collection_contract_sha256']):
            raise ValueError(f'unapproved frozen collection identity: {rid}')
        verify_frozen_acceptance(state)
        report = verify_run_evidence(rid, project)
        if report.get('status') != 'RUN_EVIDENCE_CHECK_PASS':
            raise ValueError(f'raw replay did not pass: {rid}')
    return _certificate(policy, policy_sha, commit, runtime_identity())


def verify_export_records(
    rows: list[dict[str, Any]], certificate: dict, *, root: Path,
    raw_dir: Path, evidence_dir: Path,
) -> list[dict[str, Any]]:
    """Close the audit/rediscovery gap before any partition is written."""
    policy, sha, commit = _policy(root)
    if certificate != _certificate(policy, sha, commit, runtime_identity()):
        raise ValueError('training source certificate differs from reviewed source')
    canonical = [canonical_record(row) for row in rows]
    keys = [run_key(row['run_id']) for row in canonical]
    if len(set(keys)) != len(keys) or set(keys) != set(policy['approved_runs']):
        raise ValueError('export inventory differs from reviewed runs')
    for row, key in zip(canonical, keys, strict=True):
        approved = policy['approved_runs'][key]
        if (digest(row) != approved['record_sha256'] or run_input_hash(
            raw_dir, evidence_dir, row['run_id'],
        ) != approved['input_sha256']):
            raise ValueError('export record or original input changed after audit')
    if canonical_dataset_hash(canonical) != policy['dataset_hash_sha256']:
        raise ValueError('export dataset commitment differs from review')
    return canonical


def verify_training_manifest(
    manifest: dict, rows_by_partition: dict[str, list[dict]] | None = None, *,
    root: Path | None = None, expected_commit: str | None = None,
) -> None:
    """Verify v3 without raw or locked rows; legacy v2 cannot impersonate this handoff."""
    root = Path(root) if root is not None else ROOT
    collection = manifest.get('collection_audit', {})
    provenance = manifest.get('provenance', {})
    if not isinstance(collection, dict) or not isinstance(provenance, dict):
        raise ValueError('training audit/provenance must be mappings')
    if manifest.get('manifest_version') == 'dataset-manifest-v2':
        if ('source_partitions' in manifest
                or collection.get('source_compatibility') is not None
                or provenance.get('source_compatibility_sha256') is not None):
            raise ValueError('reviewed origins require manifest v3')
        if rows_by_partition:
            # Read the policy from Git, not a mutable local replacement. This
            # check does not promote unrelated historical v2 datasets to v3.
            try:
                raw = _files(root, 'HEAD').get(POLICY_RELATIVE)
            except (OSError, ValueError, subprocess.SubprocessError):
                path = root / POLICY_RELATIVE
                raw = path.read_bytes() if path.is_file() else None
            known = json.loads(raw)['approved_runs'] if raw else {}
            if any(run_key(row['run_id']) in known
                   for rows in rows_by_partition.values() for row in rows):
                raise ValueError('reviewed run cannot downgrade to manifest v2; rebuild v3')
        return
    if manifest.get('manifest_version') != 'dataset-manifest-v3':
        raise ValueError('unsupported training manifest version')
    policy, policy_sha, commit = _policy(root)
    supplied = collection.get('source_compatibility')
    if not isinstance(supplied, dict):
        raise ValueError('reviewed source compatibility certificate is missing')
    cert = _certificate(policy, policy_sha, commit, supplied.get('processing_runtime'))
    if (collection.get('source_compatibility') != cert
            or provenance.get('source_compatibility_sha256') != digest(cert)
            or provenance.get('builder_git_commit') != commit
            or (expected_commit is not None and expected_commit != commit)
            or manifest.get('dataset_hash_sha256') != policy['dataset_hash_sha256']
            or manifest.get('locked_test_sha256') != policy['partitions']['locked_test']['sha256']
            or manifest.get('source_partitions') != policy['partitions']):
        raise ValueError('reviewed source/partition provenance differs from pinned policy')
    if (manifest.get('feature_schema_sha256') != policy['feature_schema_sha256']
            or provenance.get('collection_contract_sha256') != policy['collection_contract_sha256']
            or collection.get('collection_contract_sha256') != policy['collection_contract_sha256']
            or provenance.get('collection_design_sha256') != policy['collection_design_sha256']
            or collection.get('collection_design_sha256') != policy['collection_design_sha256']):
        raise ValueError('reviewed collection schema/design/contract provenance differs')
    counts = {name: item['record_count'] for name, item in policy['partitions'].items()}
    if (manifest.get('group_key') != 'cohort_id'
            or manifest.get('locked_test_status') != 'UNOPENED'
            or collection.get('status') != policy['audit_status']
            or collection.get('collection_candidate') is not None
            or collection.get('audit_version') != 'dataset-audit-v2'
            or not isinstance(collection.get('report_sha256'), str)
            or re.fullmatch(r'[0-9a-f]{64}', collection['report_sha256']) is None
            or provenance.get('collection_mode') != 'REAL_LAB'
            or provenance.get('builder_config_sha256') != policy['builder_config_sha256']
            or manifest.get('partition_counts') != counts
            or manifest.get('record_counts') != counts
            or manifest.get('stratum_run_counts') != policy['stratum_run_counts']
            or manifest.get('split_assignment_commitment_sha256')
            != policy['split_assignment_commitment_sha256']):
        raise ValueError('reviewed split/config/audit metadata is inconsistent')
    override = provenance.get('source_config_override')
    if override is not None and (
        not isinstance(override, dict)
        or override.get('sha256') != policy['source_config_sha256']
    ):
        raise ValueError('source override hash differs from reviewed collection contract')
    for name in PARTITIONS:
        actual = manifest.get('partitions', {}).get(name, {})
        approved = policy['partitions'][name]
        if any(actual.get(key) != approved[key] for key in ('sha256', 'record_count')):
            raise ValueError('partition bytes/count differ from reviewed commitment')
    if rows_by_partition is None:
        return
    if set(rows_by_partition) != {'train', 'validation'}:
        raise ValueError('training verifies train/validation only; never open locked test')
    seen = set()
    for name, rows in rows_by_partition.items():
        if partition_commitment(rows) != policy['partitions'][name]:
            raise ValueError('partition membership or bytes differ from reviewed split')
        for row in rows:
            key = run_key(row['run_id'])
            if (key in seen or key not in policy['approved_runs']
                    or row != canonical_record(row)
                    or digest(row) != policy['approved_runs'][key]['record_sha256']):
                raise ValueError('partition record differs from immutable reviewed origin')
            seen.add(key)
    locked = set(policy['approved_runs']) - seen
    contract = policy['partitions']['locked_test']
    if (len(locked) != contract['record_count']
            or digest(sorted(locked)) != contract['run_keys_sha256']):
        raise ValueError('locked-test membership commitment differs; do not open locked rows')
