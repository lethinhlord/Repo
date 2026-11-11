"""Evidence-bound collection release records; records are integrity checks, not signatures."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


class ReleaseError(ValueError):
    pass


def create_backup(root: Path, tag: str, output: Path) -> dict[str, Any]:
    from ml.collection_backup import create_backup as implementation

    return implementation(root, tag, output)


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError(f"git verification failed: {args}") from exc


def capture_candidate(root: Path, tag: str) -> dict[str, Any]:
    root = Path(root).resolve()
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag)
        or tag.startswith("pilot-")
        or tag == "data-collection-v2.0.0"
    ):
        raise ReleaseError("candidate must use a separate valid release tag")
    if _git(root, "remote", "get-url", "origin") not in {
        "https://github.com/lethinhlord/Repo.git",
        "git@github.com:lethinhlord/Repo.git",
    }:
        raise ReleaseError("unexpected origin")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ReleaseError("tracked source is dirty or deleted")
    ref = "refs/tags/" + tag
    if _git(root, "cat-file", "-t", ref) != "tag":
        raise ReleaseError("candidate tag must be annotated")
    commit = _git(root, "rev-parse", "HEAD")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", commit)
        or _git(root, "rev-parse", ref + "^{commit}") != commit
    ):
        raise ReleaseError("candidate tag does not identify HEAD")
    tracked = _git(root, "ls-files", "-z").split("\0")
    files = {}
    for name in tracked:
        if not name:
            continue
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"missing or unsupported tracked file: {name}")
        files[name] = _file_hash(path)
    # Include the whole tracked tree, including collection runners and contracts.
    try:
        runtime = subprocess.run(
            [sys.executable, "-m", "pip", "freeze", "--all"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.splitlines()
        node_version = subprocess.run(
            ["node", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ReleaseError("cannot inventory runtime dependencies") from exc
    return {
        "version": "collection-candidate-v1",
        "commit": commit,
        "tag": tag,
        "tag_object": _git(root, "rev-parse", ref),
        "origin": "https://github.com/lethinhlord/Repo.git",
        "tracked_files_sha256": digest(files),
        "python_version": sys.version,
        "node_version": node_version,
        "installed_packages_sha256": digest(sorted(runtime)),
    }


def verify_remote_candidate(root: Path, candidate: dict[str, Any]) -> None:
    """During connected maintenance compare both annotated tag and peeled SHA to origin."""
    ref = "refs/tags/" + candidate["tag"]
    lines = _git(root, "ls-remote", "--tags", "origin", ref, ref + "^{}")
    try:
        refs = {name: value for value, name in (line.split() for line in lines.splitlines())}
    except ValueError as exc:
        raise ReleaseError("invalid remote tag response") from exc
    if refs.get(ref) != candidate["tag_object"] or refs.get(ref + "^{}") != candidate["commit"]:
        raise ReleaseError("remote candidate tag does not match local tag and commit")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"invalid or missing release record: {path}") from exc
    if not isinstance(data, dict):
        raise ReleaseError("release record must be an object")
    return data


def _source_value(source: Any, key: str) -> Any:
    return source.get(key) if isinstance(source, dict) else getattr(source, key, None)


def assert_collection_authorized(
    source: Any, root: Path, purpose: str, source_config_path: Path | None = None,
) -> dict[str, Any] | None:
    if purpose != "trainable":
        return None
    path = _source_value(source, "collection_release_path")
    if not path:
        raise ReleaseError("trainable collection requires a configured acceptance record")
    path = Path(path)
    if not path.is_absolute():
        path = Path(root) / path
    record = _read_json(path)
    if (
        record.get("version") not in {"collection-acceptance-v1", "collection-acceptance-v2"}
        or record.get("record_sha256")
        != digest({k: v for k, v in record.items() if k != "record_sha256"})
        or not isinstance(record.get("candidate"), dict)
        or len(record.get("pilots", [])) != 4
        or not isinstance(record.get("backup"), dict)
    ):
        raise ReleaseError("invalid acceptance structure or digest")
    candidate = record["candidate"]
    if capture_candidate(root, candidate.get("tag", "")) != candidate:
        raise ReleaseError("source or runtime differs from the accepted candidate")
    options = {}
    if record["version"] == "collection-acceptance-v2":
        from ml.scenario_collection import SourceConfig, _source_document

        binding = record.get("source_config", {})
        if not isinstance(binding, dict) or not isinstance(binding.get("path"), str):
            raise ReleaseError("missing accepted source config binding")
        selected = Path(binding["path"])
        actual = SourceConfig.model_validate(source)
        if (
            not selected.is_file()
            or _file_hash(selected) != binding.get("sha256")
            or _source_document(actual) != binding.get("document")
            or (source_config_path is not None
                and _file_hash(source_config_path) != binding.get("sha256"))
        ):
            raise ReleaseError("collection source differs from the accepted source config")
        options["source_config_path"] = selected
    try:
        with tempfile.TemporaryDirectory(prefix="datn-release-check-") as temp:
            verified = create_acceptance(
                Path(root),
                candidate["tag"],
                [x["run_id"] for x in record["pilots"]],
                Path(record["backup"]["directory"]),
                Path(record["preflight_directory"]),
                Path(temp) / "acceptance.json",
                **options,
            )
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ReleaseError(f"acceptance evidence cannot be revalidated: {exc}") from exc
    if verified != record:
        raise ReleaseError("acceptance differs from current evidence")
    return record


def verify_frozen_acceptance(state: dict[str, Any]) -> None:
    snapshot = state.get("collection_release")
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("version") not in {"collection-acceptance-v1", "collection-acceptance-v2"}
        or snapshot.get("record_sha256")
        != digest({k: v for k, v in snapshot.items() if k != "record_sha256"})
        or state.get("collection_release_sha256") != digest(snapshot)
        or snapshot.get("candidate") != state.get("collection_candidate", snapshot.get("candidate"))
    ):
        raise ReleaseError("missing or altered frozen collection release")
    if snapshot["version"] == "collection-acceptance-v2":
        contract = snapshot.get("collection_contract", {})
        keys = {"source_config_sha256", "taxonomy_sha256",
                "scenario_catalog_sha256", "feature_schema_sha256"}
        if (
            not isinstance(contract, dict) or set(contract) != keys
            or any(state.get(key) != value for key, value in contract.items())
            or contract["source_config_sha256"] != snapshot.get("source_config", {}).get("sha256")
        ):
            raise ReleaseError("frozen collection source contract differs from acceptance")


def summarize_candidates(evidence_dir: Path, run_ids: list[str], tag: str) -> dict | None:
    """Reject mixed frozen software/runtime identities without requiring live Git on restore."""
    selected = None
    for rid in run_ids:
        state = _read_json(evidence_dir / rid / ".collection_state.json")
        candidate = state.get("collection_candidate")
        if (
            not isinstance(candidate, dict)
            or candidate.get("tag") != tag
            or not re.fullmatch(r"[0-9a-f]{40}", str(candidate.get("commit", "")))
            or state.get("collection_candidate_sha256") != digest(candidate)
        ):
            raise ReleaseError(f"missing or mismatched frozen candidate: {rid}")
        if selected is not None and selected != candidate:
            raise ReleaseError("dataset contains mixed candidate source/runtime identities")
        selected = candidate
    return selected


def _extract_backup(archive: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive, "r:gz") as tar:
            seen: set[str] = set()
            total_size = 0
            for item in tar:
                # Do not extract arbitrary paths, links, devices or duplicate entries.
                name = item.name.removeprefix("./")
                parts = Path(name).parts
                if (
                    not parts
                    or Path(name).is_absolute()
                    or ".." in parts
                    or "\\" in name
                    or parts[0] not in {"data", "evidence", "run-drafts", "operator-logs"}
                    or ":" in name
                    or any(
                        part.startswith(".env") or part.endswith((".pem", ".key")) for part in parts
                    )
                ):
                    raise ReleaseError("unsafe backup member")
                normalized = "/".join(parts)
                if normalized in seen or len(seen) >= 1_000_000:
                    raise ReleaseError("duplicate or excessive backup members")
                seen.add(normalized)
                allowed = normalized in {
                    "data",
                    "data/raw",
                    "data/quarantine",
                    "evidence",
                    "run-drafts",
                    "operator-logs",
                } or normalized.startswith(
                    ("data/raw/", "data/quarantine/", "evidence/", "run-drafts/", "operator-logs/")
                )
                basename = parts[-1].casefold()
                if (
                    not allowed
                    or basename.endswith((".env", ".ps1", ".whl", ".bundle", ".key", ".pem"))
                    or basename.startswith(".env")
                    or "wheelhouse" in normalized.casefold()
                ):
                    raise ReleaseError(f"backup member is not allowed: {normalized}")
                total_size += item.size
                if item.size < 0 or total_size > 50 * 1024**3:
                    raise ReleaseError("backup exceeds restore size limit")
                target = destination.joinpath(*parts)
                if item.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif item.isfile():
                    if target.exists():
                        raise ReleaseError("duplicate backup member")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stream = tar.extractfile(item)
                    if stream is None:
                        raise ReleaseError("unreadable backup member")
                    with stream, target.open("xb") as out:
                        import shutil

                        shutil.copyfileobj(stream, out)
                else:
                    raise ReleaseError("backup links and special files are not allowed")
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseError("backup extraction failed") from exc


def _check_preflight_capture(path: Path, preflight: dict[str, Any]) -> None:
    from ml.preflight import verify_preflight_capture

    try:
        actual = verify_preflight_capture(
            path,
            preflight["canary_id"],
            preflight["capture_started_at"],
            preflight["checked_at"],
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ReleaseError(f"preflight raw evidence failed: {exc}") from exc
    if actual != preflight:
        raise ReleaseError("preflight report differs from raw recomputation")


def _check_design(root: Path) -> None:
    """Enforce source-level prerequisites; human review remains a separate obligation."""
    from collections import defaultdict
    from types import SimpleNamespace

    import yaml

    from ml.collection_design import load_collection_design
    from ml.dataset import DatasetError, _assign_cohort_folds
    from ml.execution_profile import profile_intervals
    from ml.scenario_collection import ScenarioCatalog

    try:
        catalog = ScenarioCatalog.model_validate(
            yaml.safe_load((root / "config/scenario-catalog.yaml").read_text())
        )
        config = yaml.safe_load((root / "ml/training_config.yaml").read_text())
        taxonomy = yaml.safe_load((root / "config/suspicious-process-taxonomy.yaml").read_text())
        planned = [item for item in catalog.scenarios if item.purpose == "trainable"]
        if load_collection_design(root / "config/scenario-catalog.yaml") is None:
            raise ReleaseError("official collection design is missing")
        for item in catalog.scenarios:
            profile_intervals(item.execution_profile)
        folds = config["split"]["number_of_folds"]
        minimum = max(folds, config["data"]["minimum_groups_per_family_label"])
        members = defaultdict(set)
        for item in planned:
            members[(item.family, int(item.label == "malicious"))].add(item.cohort_id)
        expected = {("account", 0), ("account", 1), ("c2", 0), ("c2", 1)}
        if (
            config["data"]["group_key"] != "cohort_id"
            or set(members) != expected
            or any(len(groups - {None, ""}) < minimum for groups in members.values())
            or not any(item.purpose == "challenge" for item in catalog.scenarios)
        ):
            raise ReleaseError("catalog/cohort/challenge source contract is not ready")
        rows = {
            item.scenario_id: SimpleNamespace(
                scenario_id=item.scenario_id,
                cohort_id=item.cohort_id,
                family=item.family,
                label=int(item.label == "malicious"),
            )
            for item in planned
        }
        _assign_cohort_folds(rows, folds, config["random_seed"])
        design = yaml.safe_load((root / "config/collection-design.yaml").read_text())
        shared = design["shared_entities"]
        if (
            design.get("group_key") != "cohort_id"
            or design.get("automation_eligible") is not False
            or not isinstance(design.get("scope"), str)
            or "profiles" not in design["scope"].casefold()
        ):
            raise ReleaseError("design scope/group contract is invalid")
        rules = taxonomy.get("rules")
        if not isinstance(rules, list) or not rules:
            raise ReleaseError("taxonomy must contain rules")
        for rule in rules:
            if (
                not isinstance(rule.get("image_suffix"), str)
                or not rule["image_suffix"].strip()
                or not isinstance(rule.get("command_contains_any"), list)
                or not rule["command_contains_any"]
                or any(
                    not isinstance(term, str) or not term.strip()
                    for term in rule["command_contains_any"]
                )
            ):
                raise ReleaseError("taxonomy contains an empty or malformed rule")
        by_id = {item.scenario_id: item for item in planned}
        raw = {
            row["scenario_id"]: row
            for row in yaml.safe_load((root / "config/scenario-catalog.yaml").read_text())[
                "scenarios"
            ]
        }
        covered = set()
        for cohort in design["cohorts"]:
            ids = cohort["scenario_ids"]
            if len(ids) != 2 or len(set(ids)) != 2 or any(item not in by_id for item in ids):
                raise ReleaseError("each design cohort requires exactly two trainable scenarios")
            if covered.intersection(ids):
                raise ReleaseError("scenario occurs in multiple design cohorts")
            covered.update(ids)
            pair = [by_id[item] for item in ids]
            if {item.label for item in pair} != {"benign", "malicious"} or any(
                item.family != cohort["family"] or item.cohort_id != cohort["cohort_id"]
                for item in pair
            ):
                raise ReleaseError("catalog and paired design disagree")
            profiles = [raw[item.scenario_id]["execution_profile"] for item in pair]
            attrs = [item.attribution for item in pair]
            if profiles[0]["transport"] != profiles[1]["transport"]:
                raise ReleaseError("paired transport is class-exclusive")
            for attr in (
                "account_names",
                "process_names",
                "source_ips",
                "destination_ips",
                "destination_ports",
                "dns_suffixes",
                "command_contains_any",
                "logon_types",
            ):
                if set(getattr(attrs[0], attr)) != set(getattr(attrs[1], attr)):
                    raise ReleaseError(f"paired nuisance attribution differs: {attr}")
            if cohort["family"] == "account":
                names = set(attrs[0].account_names)
                if not names or not names <= set(shared["account_names"]):
                    raise ReleaseError("paired account identities are not declared shared")
                if profiles[0].get("accounts_csv") != profiles[1].get("accounts_csv"):
                    raise ReleaseError("paired account execution identities differ")
            elif profiles[0]["transport"] == "http":
                if (
                    any(profile.get("endpoint") != shared["http_endpoint"] for profile in profiles)
                    or set(attrs[0].process_names) != {shared["http_process"]}
                    or set(attrs[0].destination_ips) != {shared["remote_source_ip"]}
                ):
                    raise ReleaseError("paired HTTP endpoint/process is not shared")
            elif profiles[0]["transport"] == "dns":
                if any(
                    profile.get("domain_suffix") != shared["dns_suffix"]
                    or profile.get("dns_server") != shared["dns_server"]
                    for profile in profiles
                ) or set(attrs[0].process_names) != set(shared["dns_processes"]):
                    raise ReleaseError("paired DNS endpoint/process is not shared")
            else:
                raise ReleaseError("unrecognized C2 transport")
            if cohort["family"] == "c2":
                signatures = [
                    set(item.quality_gates.required_suricata_signature_ids) for item in pair
                ]
                if signatures[0] != signatures[1] or not signatures[0]:
                    raise ReleaseError("paired Suricata nuisance signature differs")
                # The same process and command attribution makes taxonomy matching symmetric.
                matches = []
                for attr in attrs:
                    matches.append(
                        {
                            rule["name"]
                            for rule in rules
                            if any(
                                image.casefold().endswith(rule["image_suffix"].casefold())
                                for image in attr.process_names
                            )
                            and any(
                                term.casefold() in command.casefold()
                                for term in rule["command_contains_any"]
                                for command in attr.command_contains_any
                            )
                        }
                    )
                if matches[0] != matches[1]:
                    raise ReleaseError("paired taxonomy matching is class-exclusive")
        if covered != set(by_id):
            raise ReleaseError("paired design omits or duplicates trainable scenarios")
        challenge = {item.scenario_id for item in catalog.scenarios if item.purpose == "challenge"}
        expectations = design["challenge_expectations"]
        if {item["scenario_id"] for item in expectations} != challenge or any(
            item.get("expected_decision") != "REVIEW" or item.get("training_eligible") is not False
            for item in expectations
        ):
            raise ReleaseError("challenge expectations are incomplete")
    except (OSError, KeyError, TypeError, ValueError, DatasetError) as exc:
        raise ReleaseError(f"invalid source design: {exc}") from exc


def create_acceptance(
    root: Path, tag: str, pilot_ids: list[str], backup_dir: Path, preflight_dir: Path, output: Path,
    *, source_config_path: Path | None = None,
) -> dict[str, Any]:
    """Revalidate actual pilots, restore and preflight artifacts before writing once."""
    from ml.scenario_collection import CollectionError, validate_run
    from scripts.verify_run_evidence import verify_run_evidence

    root = Path(root).resolve()
    candidate = capture_candidate(root, tag)
    _check_design(root)
    selected_source = None
    source_binding = None
    if source_config_path is not None:
        import yaml

        from ml.scenario_collection import SourceConfig, _source_document

        selected_source = Path(source_config_path)
        if not selected_source.is_absolute():
            selected_source = root / selected_source
        selected_source = selected_source.resolve()
        source_model = SourceConfig.model_validate(
            yaml.safe_load(selected_source.read_text(encoding="utf-8"))
        )
        if not source_model.context_baseline_path or not source_model.collection_release_path:
            raise ReleaseError("collection source requires baseline and acceptance paths")
        source_binding = {
            "path": str(selected_source), "sha256": _file_hash(selected_source),
            "document": _source_document(source_model),
        }
    if len(pilot_ids) != 4 or len(set(pilot_ids)) != 4:
        raise ReleaseError("exactly four distinct pilot IDs are required")
    current_contract = {
        "source_config_sha256": _file_hash(
            selected_source or root / "config/collection-sources.yaml"
        ),
        "taxonomy_sha256": _file_hash(root / "config/suspicious-process-taxonomy.yaml"),
        "scenario_catalog_sha256": _file_hash(root / "config/scenario-catalog.yaml"),
        "feature_schema_sha256": _file_hash(root / "ml/feature_schema.json"),
    }
    pilots = []
    strata = set()
    transports = set()
    pilot_candidate = None
    adoption = None
    for run_id in pilot_ids:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{3,127}", run_id):
            raise ReleaseError("invalid pilot run ID")
        try:
            report = verify_run_evidence(run_id, root)
        except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
            raise ReleaseError(f"pilot verification failed: {run_id}: {exc}") from exc
        state_path = root / "evidence/scenario-runs" / run_id / ".collection_state.json"
        state = _read_json(state_path)
        manifest_path = root / "data/raw" / run_id / "scenario_manifest.json"
        manifest = _read_json(manifest_path)
        frozen_candidate = state.get("collection_candidate")
        if pilot_candidate is None:
            pilot_candidate = frozen_candidate
            if source_binding is not None and pilot_candidate != candidate:
                from ml.collection_adoption import verify_pilot_adoption

                adoption = verify_pilot_adoption(root, pilot_candidate, candidate)
        if source_binding is not None:
            import yaml

            from ml.scenario_collection import SourceConfig, _source_document

            frozen_source = _source_document(SourceConfig.model_validate(yaml.safe_load(
                (state_path.parent / "collection-sources.yaml").read_text(encoding="utf-8")
            )))
            # Enrollment can be renewed without changing observation semantics.
            def semantic(doc):
                return {k: v for k, v in doc.items() if k != "context_baseline_path"}
            if semantic(frozen_source) != semantic(source_binding["document"]):
                raise ReleaseError(f"pilot source observation contract differs: {run_id}")
        expected_contract = {
            key: value for key, value in current_contract.items()
            if source_binding is None or key != "source_config_sha256"
        }
        if (
            report.get("status") != "RUN_EVIDENCE_CHECK_PASS"
            or manifest.get("purpose") != "pilot"
            or frozen_candidate != (pilot_candidate if source_binding is not None else candidate)
            or state.get("collection_candidate_sha256") != digest(frozen_candidate)
            or any(state.get(key) != value for key, value in expected_contract.items())
        ):
            raise ReleaseError(f"pilot lacks passing evidence and frozen candidate: {run_id}")
        stratum = (manifest.get("family"), manifest.get("label"))
        strata.add(stratum)
        transports.add(state.get("draft", {}).get("scenario_parameters", {}).get("transport"))
        pilots.append(
            {
                "run_id": run_id,
                "manifest_sha256": _file_hash(manifest_path),
                "state_sha256": _file_hash(state_path),
                "checksums_sha256": _file_hash(state_path.parent / "checksums.sha256"),
            }
        )
    if strata != {
        ("account", "benign"),
        ("account", "malicious"),
        ("c2", "benign"),
        ("c2", "malicious"),
    }:
        raise ReleaseError("pilots must cover all four family/label strata")
    if transports != {"console", "smb", "http", "dns"}:
        raise ReleaseError("pilots must cover console, SMB, HTTP and DNS transports")
    preflight_dir = Path(preflight_dir).resolve()
    fresh = preflight_dir / "archives-fresh.jsonl"
    check = preflight_dir / "channel-check.txt"
    checksum = preflight_dir / "capture.sha256"
    if not all(p.is_file() and p.stat().st_size for p in (fresh, check, checksum)):
        raise ReleaseError("actual preflight capture, check and checksums required")
    try:
        entries = dict(
            line.split("  ", 1)[::-1] for line in checksum.read_text().splitlines() if line.strip()
        )
    except ValueError as exc:
        raise ReleaseError("invalid preflight checksums") from exc

    def has_checksum(path: Path) -> bool:
        return any(
            expected == _file_hash(path)
            and (
                Path(name).resolve() == path or (root / name).resolve() == path or name == path.name
            )
            for name, expected in entries.items()
        )

    if not all(has_checksum(p) for p in (fresh, check)):
        raise ReleaseError("preflight checksum mismatch")
    # The original canary verifier emits a JSON object, rather than a pasted PASS token.
    preflight = _read_json(check)
    if (
        not preflight.get("canary_id")
        or preflight.get("http_ports") != [8080, 8081, 9001]
        or preflight.get("flow_issues") != []
        or preflight.get("sysmon_time_rows", 0) < 3
        or preflight.get("final_connections", 0) < 1
    ):
        raise ReleaseError("preflight channel result is incomplete")
    _check_preflight_capture(fresh, preflight)
    backup_dir = Path(backup_dir).resolve()
    archives = list(backup_dir.glob("collection-*.tar.gz"))
    if len(archives) != 1:
        raise ReleaseError("backup directory must contain exactly one archive")
    archive = archives[0]
    checksum_file = backup_dir / "checksums.sha256"
    try:
        backup_checksums = dict(
            line.split("  ", 1)[::-1]
            for line in checksum_file.read_text().splitlines()
            if line.strip()
        )
    except (OSError, ValueError) as exc:
        raise ReleaseError("missing or invalid backup checksums") from exc
    if backup_checksums.get(archive.name) != _file_hash(archive):
        raise ReleaseError("backup archive checksum mismatch")
    backup_candidate = pilot_candidate if source_binding is not None else candidate
    for name, expected in (
        ("git-commit.txt", backup_candidate["commit"]),
        ("source-tag.txt", backup_candidate["tag"]),
        ("source-tag-object.txt", backup_candidate["tag_object"]),
        ("source-url.txt", backup_candidate["origin"]),
    ):
        if (
            backup_checksums.get(name) != _file_hash(backup_dir / name)
            or (backup_dir / name).read_text(encoding="utf-8").strip() != expected
        ):
            raise ReleaseError(f"backup source mismatch: {name}")
    with tempfile.TemporaryDirectory(prefix="datn-release-restore-") as temp:
        restored = Path(temp)
        _extract_backup(archive, restored)
        for item in pilots:
            run_id = item["run_id"]
            for rel, key in (
                (f"data/raw/{run_id}/scenario_manifest.json", "manifest_sha256"),
                (f"evidence/scenario-runs/{run_id}/.collection_state.json", "state_sha256"),
                (f"evidence/scenario-runs/{run_id}/checksums.sha256", "checksums_sha256"),
            ):
                if _file_hash(restored / rel) != item[key]:
                    raise ReleaseError(f"backup differs from pilot evidence: {rel}")
            try:
                validate_run(run_id, restored)
            except (CollectionError, OSError, ValueError, KeyError, TypeError) as exc:
                raise ReleaseError(f"restored pilot verification failed: {run_id}: {exc}") from exc
    record = {
        "version": "collection-acceptance-v1",
        "candidate": candidate,
        "pilots": pilots,
        "preflight_directory": str(preflight_dir),
        "preflight_capture_sha256": _file_hash(fresh),
        "preflight_check_sha256": _file_hash(check),
        "backup": {
            "directory": str(backup_dir),
            "archive_sha256": _file_hash(archive),
            "restored_pilots": pilot_ids,
        },
    }
    if source_binding is not None:
        record.update(
            version="collection-acceptance-v2", source_config=source_binding,
            collection_contract=current_contract, pilot_candidate=pilot_candidate,
            pilot_adoption=adoption,
        )
    record["record_sha256"] = digest(record)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError as exc:
        raise ReleaseError("acceptance already exists; never overwrite it") from exc
    return record
