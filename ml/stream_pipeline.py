"""Opt-in stream profile, sharing legacy evidence proof and full-window values."""
from __future__ import annotations

import os
from typing import Any

from api.app.contracts import (
    IndicatorAttribution,
    StreamFeatureBatchResponse,
    StreamFeaturePipelineResponse,
    StreamIncidentRequest,
    WazuhAlert,
)
from ml.behavior_features import FEATURE_ORDER
from ml.context import BaselineSnapshot, load_baseline
from ml.feature_pipeline import (
    ROOT,
    _collection_config,
    aggregate_wazuh_alerts,
    derive_c2_network_evidence,
)
from ml.stream_features import (
    STREAM_FEATURES,
    STREAM_SCHEMA_VERSION,
    derive_stream_features,
    dominant_tcp_conversation,
)
from ml.telemetry import windows_fields

STREAM_FEATURE_ORDER = (*FEATURE_ORDER, *STREAM_FEATURES)


def aggregate_stream_alerts(
    alerts: list[WazuhAlert], *, window_minutes: int = 5,
    baseline: BaselineSnapshot | None = None, source_config: dict[str, Any] | None = None,
    taxonomy: dict[str, Any] | None = None, use_runtime_baseline: bool = True,
    process_context: list[WazuhAlert] | None = None,
) -> StreamFeatureBatchResponse:
    config = _collection_config() if source_config is None else source_config
    if baseline is None and use_runtime_baseline:
        path = os.getenv("CONTEXT_BASELINE_PATH") or config.get("context_baseline_path")
        baseline = load_baseline(ROOT / path) if path else None
    old = aggregate_wazuh_alerts(
        alerts, window_minutes=window_minutes, baseline=baseline, source_config=config,
        taxonomy=taxonomy, use_runtime_baseline=False, process_context=process_context,
    )
    by_id = {a.id: a for a in alerts}
    identities = [a for a in [*(process_context or []), *alerts]
                  if windows_fields(a.model_dump(mode="json"))[0] in {"1", "5"}]
    result = []
    for response in old.incidents:
        incident = response.incident
        features = {**incident.features, **dict.fromkeys(STREAM_FEATURES, 0.0)}
        indicator, attribution = incident.indicator, None
        if incident.family_hint == "c2":
            members = [by_id[ref.removeprefix("wazuh-alert:")]
                       for ref in incident.raw_refs if ref.startswith("wazuh-alert:")]
            proof = derive_c2_network_evidence(members, config, taxonomy, identities)
            extra = derive_stream_features(list(proof.streams), baseline=baseline,
                                           asset_id=incident.asset_id)
            features.update(extra)
            dominant = dominant_tcp_conversation(list(proof.streams))
            # A tie does not prove which peer should represent the window.
            indicator = dominant[0].network.destination if dominant else None
            if dominant:
                history = bool(extra["dominant_tcp_context_known"])
                attribution = IndicatorAttribution(
                    destination=indicator,
                    destination_port=dominant[0].network.destination_port,
                    observation_count=len(dominant), history_known=history,
                    new_destination=(
                        bool(extra["dominant_tcp_new_destination"]) if history else None
                    ),
                    evidence_refs=sorted({f"wazuh-alert:{x.source_event_id}" for x in dominant}),
                )
        payload = incident.model_dump()
        payload.update(feature_schema_version=STREAM_SCHEMA_VERSION, features=features,
                       indicator=indicator, indicator_attribution=attribution)
        structural = list(response.structural_zero_features)
        if incident.family_hint != "c2":
            structural.extend(STREAM_FEATURES)
        values = response.model_dump(exclude={"incident"})
        values.update(
            feature_schema_version=STREAM_SCHEMA_VERSION,
            feature_order=list(STREAM_FEATURE_ORDER),
            ordered_vector=[features[n] for n in STREAM_FEATURE_ORDER],
            structural_zero_features=structural,
            incident=StreamIncidentRequest(**payload),
        )
        result.append(StreamFeaturePipelineResponse(**values))
    return StreamFeatureBatchResponse(
        **{**old.model_dump(exclude={"incidents"}),
           "feature_schema_version": STREAM_SCHEMA_VERSION, "incidents": result},
    )
