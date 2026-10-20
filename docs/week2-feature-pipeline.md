# Week 2 Feature Pipeline v1

The pipeline has two explicit stages:

1. `extract_wazuh_features` validates and normalizes one raw Wazuh alert.
2. `aggregate_wazuh_alerts` deduplicates by alert ID and groups compatible events
   into a configurable half-open 1–5 minute window.

Account incidents are grouped by normalized asset and destination user. C2
incidents are grouped by normalized asset and destination indicator. Counts are
summed; binary and periodicity features use the maximum. Conflicting duplicate
IDs are rejected rather than silently selecting one payload.

`features-v1` is a minimal Week 2 vector intended to prove the pipeline and
interface. It is not the final Week 3 training schema. Cross-family slots are
structural zeros and are reported separately from missing required features.
Only missing applicable fields make the output `PARTIAL`.

Evidence source means an independent sensor, not a file name. A Wazuh event
therefore records `evidence_sources=["wazuh"]`; the underlying log is retained
as a raw reference. TI and asset criticality are excluded from the ML vector and
are added only in the Risk layer.
