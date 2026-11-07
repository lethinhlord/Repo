import json

import pytest
import test_collection_acceptance as fixture
import test_official_collection_acceptance as official

from ml.collection_release import ReleaseError, create_backup
from ml.scenario_collection import CollectionError


@pytest.mark.parametrize(
    "scenario_id,damage",
    [
        ("C2-MALICIOUS-HTTP-BEACON", "missing"),
        ("C2-MALICIOUS-HTTP-BEACON", "missing_multiple"),
        ("C2-BENIGN-DNS", "missing"),
        ("C2-MALICIOUS-HTTP-BEACON", "wrong_http"),
        ("C2-BENIGN-DNS", "failed_dns"),
        ("C2-BENIGN-DNS", "missing_answer"),
        ("C2-MALICIOUS-HTTP-BEACON", "duplicate"),
        ("C2-BENIGN-DNS", "ambiguous"),
        ("C2-MALICIOUS-HTTP-BEACON", "wrong_sequence"),
        ("C2-MALICIOUS-HTTP-BEACON", "wrong_status"),
        ("C2-MALICIOUS-HTTP-BEACON", "wrong_method"),
        ("C2-MALICIOUS-HTTP-BEACON", "wrong_variant"),
        ("C2-MALICIOUS-HTTP-BEACON", "wrong_path"),
    ],
)
def test_official_c2_requires_each_successful_transaction(
    tmp_path, monkeypatch, scenario_id, damage
):
    root = tmp_path / "lab"
    root.mkdir()
    archive, source, catalog, _ = official.prepare_official(root, monkeypatch)
    original = fixture._c2_events

    def altered(*args):
        rows, end = original(*args)
        if damage in {"missing", "missing_multiple"}:
            rows = [
                r
                for r in rows
                if "full_log" not in r
                or not str(json.loads(r["full_log"]).get("flow_id", "")).endswith(
                    ("-0", "-1") if damage == "missing_multiple" else ("-0",)
                )
            ]
        elif damage in {"duplicate", "ambiguous"}:
            for row in rows:
                if "full_log" in row:
                    payload = json.loads(row["full_log"])
                    if payload.get("event_type") in {"http", "dns"}:
                        copy = dict(row)
                        if damage == "ambiguous":
                            payload["flow_id"] = "competing-flow"
                            payload["src_port"] += 100
                            copy["full_log"] = json.dumps(payload)
                        rows.append(copy)
                        break
        elif damage in {
            "wrong_http",
            "wrong_sequence",
            "wrong_status",
            "wrong_method",
            "wrong_variant",
            "wrong_path",
        }:
            for row in rows:
                if "full_log" in row:
                    p = json.loads(row["full_log"])
                    if p.get("event_type") == "http":
                        if damage == "wrong_http":
                            p["http"].update(
                                url="/wrong?run="
                                + args[2].scenario_parameters["run_nonce"]
                                + "&n=999",
                                status=500,
                            )
                        elif damage == "wrong_sequence":
                            p["http"]["url"] = p["http"]["url"].replace("n=1", "n=99")
                        elif damage == "wrong_status":
                            p["http"]["status"] = 500
                        elif damage == "wrong_method":
                            p["http"]["http_method"] = "POST"
                        elif damage == "wrong_variant":
                            p["http"]["url"] = p["http"]["url"].replace("&v=", "&v=9")
                        else:
                            p["http"]["url"] = p["http"]["url"].replace("/beacon?", "/wrong?")
                        row["full_log"] = json.dumps(p)
        else:
            for row in rows:
                win = row.get("data", {}).get("win", {})
                if win.get("system", {}).get("eventID") == "22":
                    win["eventdata"].update(
                        queryStatus="9003" if damage == "failed_dns" else "0", queryResults=""
                    )
        return rows, end

    monkeypatch.setattr(fixture, "_c2_events", altered)
    scenario = next(s for s in catalog.scenarios if s.scenario_id == scenario_id)
    with pytest.raises(CollectionError):
        fixture._collect_run(root, archive, source, scenario, sequence=0, repeat=0, purpose="pilot")


def test_backup_rejects_finalized_run_with_missing_manifest(tmp_path, monkeypatch):
    root = tmp_path / "lab"
    root.mkdir()
    archive, source, catalog, candidate = official.prepare_official(root, monkeypatch)
    ids = []
    for i, name in enumerate(
        ["ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS", "ACCOUNT-MALICIOUS-REPEATED-FAILURES-6"]
    ):
        scenario = next(s for s in catalog.scenarios if s.scenario_id == name)
        ids.append(
            fixture._collect_run(
                root, archive, source, scenario, sequence=i, repeat=0, purpose="pilot"
            )
        )
    (root / "data/raw" / ids[1] / "scenario_manifest.json").unlink()
    with pytest.raises((ReleaseError, CollectionError)):
        create_backup(root, candidate["tag"], tmp_path / "backup")


def test_backup_inventory_records_aborted_and_rejects_orphan_raw(tmp_path):
    from ml.collection_backup import _run_inventory

    state = tmp_path / "evidence/scenario-runs/aborted/.collection_state.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"run_id": "aborted", "status": "ABORTED"}))
    assert _run_inventory(tmp_path) == ([], ["aborted"])
    (tmp_path / "data/raw/orphan").mkdir(parents=True)
    with pytest.raises(ReleaseError, match="inventories disagree"):
        _run_inventory(tmp_path)
