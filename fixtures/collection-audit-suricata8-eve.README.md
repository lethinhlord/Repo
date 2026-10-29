# Offline EVE counter fixture

`collection-audit-suricata8-eve.jsonl` is unmodified EVE output produced during the
2026-10-28 handoff audit by Suricata 8.0.7 processing a locally generated synthetic
PCAP. No packets were sent to a network interface. The fixture is software test
evidence, not a real training dataset or acceptance of the four-VM deployment.

- Image: `jasonish/suricata:8.0.7` (community-maintained image).
- Image digest: `sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26`.
- EVE SHA-256: `9591088daa4aa63f112cc091689a81db7599e0611c035f7f2706f386b458470b`.
- Source generation and PCAP are retained in the external audit evidence directory:
  `D:\DataCodex\2026-10-05\c\outputs\handoff-audit-20261028\suricata-probe`.
- Source PCAP generator: `pcap_probe.py` in that audit directory's parent.

The HTTP request/response flow has final counters 335 + 319 = **654 bytes**;
its alert carries an earlier cumulative snapshot of 281 + 211 = 492 bytes. Those
snapshots must not be summed to claim 1,146 bytes for that same flow.

The benign DNS request/response flow has final counters 93 + 109 = **202 bytes**.
The alert carries only the 93-byte request side; the final `flow` record has no DNS
query-name field, so correlation must retain the link to the DNS transaction.

The one-flow tests reduce catalog quality gates to isolate the derivation function.
They do not demonstrate a finalized full-catalog run, sensor placement, real
Sysmon telemetry, or model detection quality. Windows envelopes in those tests
are synthetic and explicitly identified as such.
