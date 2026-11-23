"""Compile template definitions into explicitly versioned context instances."""

from __future__ import annotations

from copy import deepcopy

from ml.http_workflow import declared_workflow
from ml.supplemental_design import slots, validate_design
from ml.training_sources import digest

PILOTS = (
    "ACCOUNT-BENIGN-TWO-TYPOS-THEN-SUCCESS",
    "ACCOUNT-MALICIOUS-REPEATED-FAILURES-6",
    "C2-BENIGN-DNS",
    "C2-MALICIOUS-HTTP-BEACON",
)


def _instances(design: dict, definitions: dict) -> list[dict]:
    result = []
    for slot in slots(design):
        for label in ("benign", "malicious"):
            row = deepcopy(definitions[f"{slot['template_id']}:{label}"])
            row.update(
                scenario_id=f"{slot['cohort_id']}-{label[0].upper()}",
                template_id=slot["template_id"],
                cohort_id=slot["cohort_id"],
                purpose="trainable",
            )
            result.append(row)
    return result


def compile_catalog(design: dict, legacy_catalog: dict) -> dict:
    from ml.scenario_collection import ScenarioCatalog

    validate_design(design)
    legacy = ScenarioCatalog.model_validate(legacy_catalog).model_dump(mode="json")
    if legacy["version"] != "scenario-catalog-v1":
        raise ValueError("supplemental templates require their explicit legacy source definitions")
    source = {s["scenario_id"]: s for s in legacy["scenarios"]}
    definitions = {}
    for family, pairs in design["templates"].items():
        for pair in pairs:
            for label in ("benign", "malicious"):
                row = deepcopy(source[pair[label]])
                if row["family"] != family or row["label"] != label:
                    raise ValueError("template source identity differs from design")
                row["template_id"] = pair["id"]
                if family == "c2":
                    profile = declared_workflow(pair["id"], label)
                    row["execution_profile"] = profile
                    count = profile["expected_action_count"]
                    row["quality_gates"].update(
                        min_process_events=count,
                        min_network_events=count,
                        min_suricata_events=count,
                    )
                    row["expected_behavior"] = (
                        "Controlled lab HTTP activity profile with frozen methods, inert payload "
                        "sizes and timing. The label describes emulation provenance, not intent "
                        "inferred from a URI, address or process name."
                    )
                    row["execution_steps"] = [
                        "Use run_supplemental_http.ps1 with exported frozen parameters.",
                        "Keep the same tool, endpoint and parent setup for both cohort members.",
                    ]
                    row["expected_observables"] = [
                        "One proven native TCP connection per HTTP action, exact method/response "
                        "size, complete EVE transaction and final flow for every action."
                    ]
                definitions[f"{pair['id']}:{label}"] = row
    pilots = [{**deepcopy(source[name]), "purpose": "pilot"} for name in PILOTS]
    # G7's HTTP transport pilot exercises the new GET/POST wire contract too;
    # a legacy GET-only smoke cannot certify the supplemental runner/telemetry.
    pilots[-1]["execution_profile"] = declared_workflow("tcp-poll", "malicious")
    pilots[-1]["execution_steps"] = ["Use run_supplemental_http.ps1 with frozen parameters."]
    pilots[-1]["expected_behavior"] = (
        "Inert GET/POST transport canary for the supplemental HTTP evidence contract."
    )
    challenges = [deepcopy(s) for s in legacy["scenarios"] if s["purpose"] == "challenge"]
    result = {
        "version": "scenario-catalog-v2",
        "lab_only": True,
        "campaign_design": deepcopy(design),
        "design_sha256": digest(design),
        "template_definitions": definitions,
        "scenarios": _instances(design, definitions) + pilots + challenges,
    }
    validate_catalog(result)
    return result


def validate_catalog(doc: dict) -> dict:
    from ml.execution_profile import profile_intervals

    if (
        not isinstance(doc, dict)
        or set(doc)
        != {
            "version",
            "lab_only",
            "campaign_design",
            "design_sha256",
            "template_definitions",
            "scenarios",
        }
        or doc["version"] != "scenario-catalog-v2"
        or doc["lab_only"] is not True
    ):
        raise ValueError("invalid supplemental catalog header")
    d = doc["campaign_design"]
    validate_design(d)
    if doc["design_sha256"] != digest(d):
        raise ValueError("compiled catalog design commitment differs")
    definitions = doc["template_definitions"]
    expected = set()
    for family, pairs in d["templates"].items():
        for pair in pairs:
            attrs = []
            for label in ("benign", "malicious"):
                key = f"{pair['id']}:{label}"
                expected.add(key)
                base = definitions.get(key, {})
                if (
                    base.get("scenario_id") != pair[label]
                    or base.get("family") != family
                    or base.get("label") != label
                    or base.get("template_id") != pair["id"]
                    or base.get("purpose") != "trainable"
                ):
                    raise ValueError("compiled template differs from declared source identity")
                profile_intervals(base["execution_profile"])
                if family == "c2" and base["execution_profile"] != declared_workflow(
                    pair["id"], label
                ):
                    raise ValueError("HTTP workflow differs from its predeclared source")
                attrs.append(base["attribution"])
            if attrs[0] != attrs[1]:
                raise ValueError("paired tool, identities, endpoint and attribution must be shared")
    if set(definitions) != expected:
        raise ValueError("compiled template inventory differs")
    planned = [s for s in doc["scenarios"] if s["purpose"] == "trainable"]
    if planned != _instances(d, definitions):
        raise ValueError("catalog context instances differ from their templates/design")
    pilots = [s for s in doc["scenarios"] if s["purpose"] == "pilot"]
    challenges = [s for s in doc["scenarios"] if s["purpose"] == "challenge"]
    if (
        tuple(s["scenario_id"] for s in pilots) != PILOTS
        or len(challenges) != 8
        or len(doc["scenarios"]) != len(planned) + len(pilots) + len(challenges)
    ):
        raise ValueError("supplemental canary/challenge coverage is incomplete")
    return d
