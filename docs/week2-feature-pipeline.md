# Week 2 Feature Pipeline v2

The pipeline has two explicit stages:

1. `extract_wazuh_features` validates and normalizes one raw Wazuh alert.
2. `aggregate_wazuh_alerts` deduplicates by alert ID and groups compatible raw
   events into a configurable half-open 1–5 minute window.
3. `POST /features/wazuh/stateful` persists individual webhook events in SQLite,
   rejects conflicting replays and re-derives the incident from the complete
   five-minute window after every event. The Docker volume survives API restarts;
   old rows are pruned by receive time after 24 hours by default.

Account events correlate failures and successes by normalized asset, target
account and source. C2 events combine Sysmon network/DNS observations with
Suricata alert/flow evidence. Both the online pipeline and offline Collector use
the same functions in `ml/behavior_features.py`. Conflicting duplicate IDs are
rejected rather than silently selecting one payload.

`features-v2` adds account-rate, source diversity, remote-logon, DNS, interval,
destination-diversity, Suricata-severity and flow-volume signals needed to
distinguish behavior rather than scenario identities. Cross-family slots are
structural zeros and are reported separately from missing required features.
Only missing applicable fields make the output `PARTIAL`.

Evidence source means an independent sensor, not a file name. A Wazuh event
therefore records `evidence_sources=["wazuh"]`; the underlying log is retained
as a raw reference. TI and asset criticality are excluded from the ML vector and
are added only in the Risk layer.
