"""Synthetic protocol E2E; never certifies that Kiên's four VMs were exercised."""

import hashlib
import json
import shutil
from datetime import timedelta
from pathlib import Path

import pytest
import test_collection_acceptance as fixture
import yaml
from test_preflight_report_binding import NONCE, START, canary_rows

from ml import collection_release as release
from ml.context import build_baseline, with_dns_suffix_history
from ml.preflight import verify_preflight_capture
from ml.scenario_collection import CollectionError, ScenarioCatalog

ROOT = Path(__file__).resolve().parents[1]


def _native(event):
    win = event.get("data", {}).get("win")
    if win and win["system"]["eventID"] in {"1", "3", "22"}:
        win["system"]["providerName"] = "Microsoft-Windows-Sysmon"
        win["eventdata"]["utcTime"] = win["system"]["systemTime"]
    return event


def _account_events(run_id, scenario, draft, first):
    actions = draft.scenario_parameters["attempts_csv"].split(",")
    gaps = [
        float(s) for s in draft.scenario_parameters["expected_intervals_seconds"].split(",") if s
    ]
    at = first
    rows = []
    for i, action in enumerate(actions):
        user, result = action.split(":")
        kind = scenario.attribution.logon_types[0]
        rows.append(
            fixture._windows_event(
                run_id,
                at,
                4624 if result == "success" else 4625,
                {
                    "targetUserName": user,
                    "logonType": str(kind),
                    "ipAddress": "10.40.0.10" if kind == 3 else "127.0.0.1",
                },
                i,
            )
        )
        if i < len(gaps):
            at += timedelta(seconds=gaps[i])
    return rows, at


def prepare_official(root, monkeypatch):
    archive, source, _ = fixture._prepare_collection_root(root)
    for rel in (
        "config/scenario-catalog.yaml",
        "config/collection-design.yaml",
        "ml/training_config.yaml",
    ):
        shutil.copyfile(ROOT / rel, root / rel)
    config = yaml.safe_load(source.read_text())
    config["collection_release_path"] = "evidence/collection-acceptance.json"
    source.write_text(yaml.safe_dump(config))
    at = fixture.COLLECTION_BASE - timedelta(minutes=10)
    events = []
    for user in ("datn_lab01", "datn_lab02", "datn_lab03"):
        for ip, kind in [("127.0.0.1", 2), ("10.40.0.10", 3)]:
            events.append(
                fixture._windows_event(
                    "ENROLL",
                    at,
                    4624,
                    {"targetUserName": user, "ipAddress": ip, "logonType": str(kind)},
                    len(events),
                )
            )
    events.extend(
        [
            _native(
                fixture._windows_event(
                    "ENROLL",
                    at,
                    3,
                    {
                        "image": "curl.exe",
                        "initiated": "true",
                        "sourceIp": "10.20.0.10",
                        "destinationIp": "10.40.0.10",
                        "destinationPort": "8081",
                    },
                    len(events),
                )
            ),
            _native(
                fixture._windows_event(
                    "ENROLL",
                    at,
                    22,
                    {"image": "powershell.exe", "queryName": "www.datn.test"},
                    len(events) + 1,
                )
            ),
        ]
    )
    capture = "".join(json.dumps(e) + "\n" for e in events).encode()
    digest = hashlib.sha256(capture).hexdigest()
    baseline = with_dns_suffix_history(
        build_baseline(
            events,
            revision="SYNTHETIC-OFFICIAL",
            captured_at=at,
            valid_until=at + timedelta(days=3),
            source_capture_sha256=digest,
        ),
        ["datn.test"],
    )
    (root / "evidence/context-baseline.json").write_text(baseline.model_dump_json())
    (root / f"evidence/context-captures/{digest}.jsonl").write_bytes(capture)
    candidate = {
        "version": "collection-candidate-v1",
        "commit": "a" * 40,
        "tag": yaml.safe_load(
            (root / "config/collection-design.yaml").read_text()
        )["candidate_tag"],
        "tag_object": "b" * 40,
        "origin": "https://github.com/lethinhlord/Repo.git",
        "tracked_files_sha256": "c" * 64,
        "python_version": "synthetic-test",
        "node_version": "synthetic-test",
        "installed_packages_sha256": "d" * 64,
    }
    monkeypatch.setattr(release, "capture_candidate", lambda *args: candidate)
    monkeypatch.setattr(fixture, "_account_events", _account_events)
    original = fixture._c2_events

    def c2(*args):
        rows, end = original(*args)
        return [_native(e) for e in rows], end

    monkeypatch.setattr(fixture, "_c2_events", c2)
    return (
        archive,
        source,
        ScenarioCatalog.model_validate(
            yaml.safe_load((root / "config/scenario-catalog.yaml").read_text())
        ),
        candidate,
    )


def accept_official_lab(tmp_path, monkeypatch):
    archive, source, catalog, candidate = prepare_official(tmp_path, monkeypatch)
    selected = [
        "ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS",
        "ACCOUNT-MALICIOUS-REPEATED-FAILURES-6",
        "C2-BENIGN-DNS",
        "C2-MALICIOUS-HTTP-BEACON",
    ]
    ids = []
    for i, name in enumerate(selected):
        scenario = next(s for s in catalog.scenarios if s.scenario_id == name)
        ids.append(
            fixture._collect_run(
                tmp_path, archive, source, scenario, sequence=i, repeat=0, purpose="pilot"
            )
        )
    preflight = tmp_path / "operator-logs/preflight/UNIT"
    preflight.mkdir(parents=True)
    fresh = preflight / "archives-fresh.jsonl"
    fresh.write_text("".join(json.dumps(row) + "\n" for row in canary_rows()))
    report = verify_preflight_capture(
        fresh, NONCE.lower(), START.isoformat(), (START + timedelta(minutes=5)).isoformat()
    )
    (preflight / "channel-check.txt").write_text(json.dumps(report))
    (preflight / "capture.sha256").write_text(
        "".join(
            f"{hashlib.sha256((preflight / n).read_bytes()).hexdigest()}  {n}\n"
            for n in ("archives-fresh.jsonl", "channel-check.txt")
        )
    )
    backup = tmp_path.parent / (tmp_path.name + "-backup")
    backup_report = release.create_backup(tmp_path, candidate["tag"], backup)
    assert backup_report["status"] == "BACKUP_RESTORED_AND_VALIDATED"
    assert sorted(backup_report["validated_runs"]) == sorted(ids)
    accepted = release.create_acceptance(
        tmp_path,
        candidate["tag"],
        ids,
        backup,
        preflight,
        tmp_path / "evidence/collection-acceptance.json",
    )
    assert len(accepted["pilots"]) == 4
    return archive, source, catalog, candidate, accepted, backup, selected


def test_official_pilots_acceptance_backup_and_trainable_start(tmp_path, monkeypatch):
    archive, source, catalog, _, accepted, backup, selected = accept_official_lab(
        tmp_path, monkeypatch
    )
    scenario = next(s for s in catalog.scenarios if s.scenario_id == selected[0])
    trained = fixture._collect_run(tmp_path, archive, source, scenario, sequence=4, repeat=1)
    state = json.loads(
        (tmp_path / "evidence/scenario-runs" / trained / ".collection_state.json").read_text()
    )
    assert state["collection_release"] == accepted
    release.verify_frozen_acceptance(state)
    # Existing approval never hides missing or changed artifacts at the next run.
    next(backup.glob("collection-*.tar.gz")).unlink()
    with pytest.raises(CollectionError, match="release gate"):
        fixture._collect_run(tmp_path, archive, source, scenario, sequence=5, repeat=2)
    assert not (tmp_path / "evidence/scenario-runs/.active-run.json").exists()


def test_official_40_fresh_trainable_runs_reach_cohort_split_without_pilots(tmp_path, monkeypatch):
    from ml import build_dataset as builder

    archive, source, catalog, _, _, _, _ = accept_official_lab(tmp_path, monkeypatch)
    sequence = 4
    for repeat in (10, 11):
        for scenario in catalog.scenarios:
            if scenario.purpose != "trainable":
                continue
            fixture._collect_run(
                tmp_path, archive, source, scenario, sequence=sequence, repeat=repeat
            )
            sequence += 1
    report = fixture._audit(tmp_path, source)
    fixture._assert_balanced_report(
        report,
        expected_status="READY",
        expected_runs_per_stratum=10,
        expected_scenario_counts=[2, 2, 2, 2, 2],
    )
    assert report["split_group_key"] == "cohort_id"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(builder, "_git_commit", lambda: "a" * 40)
    manifest = builder.build_dataset(Path("ml/training_config.yaml"))
    assert manifest["group_key"] == "cohort_id"
    assert sum(manifest["record_counts"].values()) == 40
    assert manifest["locked_test_status"] == "UNOPENED"
    assert manifest["provenance"]["collection_design_sha256"]
    partitions = {}
    for name in ("train", "validation", "locked_test"):
        rows = [
            json.loads(s)
            for s in (tmp_path / f"data/processed/{name}.jsonl").read_text().splitlines()
        ]
        assert all(r["purpose"] == "trainable" for r in rows)
        partitions[name] = {r["cohort_id"] for r in rows}
    assert not (partitions["train"] & partitions["validation"])
    assert not (partitions["train"] & partitions["locked_test"])
    assert not (partitions["validation"] & partitions["locked_test"])


def test_every_official_profile_can_collect_and_replay_raw(tmp_path, monkeypatch):
    archive, source, catalog, _ = prepare_official(tmp_path, monkeypatch)
    for index, scenario in enumerate(catalog.scenarios):
        purpose = "challenge" if scenario.purpose == "challenge" else "pilot"
        fixture._collect_run(
            tmp_path, archive, source, scenario, sequence=index, repeat=0, purpose=purpose
        )


def test_delivered_enrollment_check_executes_against_rebuilt_history(tmp_path, monkeypatch):
    import re

    prepare_official(tmp_path, monkeypatch)
    guide = (ROOT / "docs/scenario-collection-runbook.md").read_text(encoding="utf-8")
    blocks = re.findall(r"<<'PY'\n(.*?)^PY$", guide, re.M | re.S)
    block = next(b for b in blocks if "ENROLLMENT_REBUILD_AND_INVENTORY=PASS" in b)
    monkeypatch.chdir(tmp_path)
    exec(compile(block, "runbook-enrollment-check", "exec"), {})
