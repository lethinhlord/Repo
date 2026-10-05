from api.app.contracts import (
    IncidentRequest,
    PredictionResponse,
    ThreatIntelligenceContext,
)

MALICIOUS_INDICATORS = {"203.0.113.66", "malicious.example"}
CLEAN_INDICATORS = {"198.51.100.10", "safe.example"}


def predict_mock(incident: IncidentRequest) -> PredictionResponse:
    features = incident.features
    if incident.family_hint == "account":
        malicious = (
            features.get("failed_login_count", 0.0) >= 10.0
            or features.get("success_after_fail", 0.0) >= 1.0
        )
        probability = 0.95 if malicious else 0.15
    elif incident.family_hint == "c2":
        malicious = (
            features.get("suspicious_process", 0.0) >= 1.0
            and features.get("periodicity_score", 0.0) >= 0.5
        ) or features.get("suricata_alert_count", 0.0) >= 1.0
        probability = 0.93 if malicious else 0.18
    else:
        malicious = incident.base_severity >= 10
        probability = 0.85 if malicious else 0.2

    return PredictionResponse(
        predicted_class="malicious" if malicious else "benign",
        malicious_probability=probability,
        family=incident.family_hint,
    )


def lookup_ti_mock(indicator: str | None) -> ThreatIntelligenceContext:
    if indicator in MALICIOUS_INDICATORS:
        return ThreatIntelligenceContext(
            indicator=indicator,
            status="MALICIOUS",
            score=0.9,
            rationale="Indicator is present in the deterministic malicious fixture set.",
        )
    if indicator in CLEAN_INDICATORS:
        return ThreatIntelligenceContext(
            indicator=indicator,
            status="CLEAN",
            score=0.1,
            rationale="Indicator is present in the deterministic clean fixture set.",
        )
    return ThreatIntelligenceContext(
        indicator=indicator,
        status="UNKNOWN",
        score=0.0,
        rationale="No deterministic mock intelligence is available for this indicator.",
    )
