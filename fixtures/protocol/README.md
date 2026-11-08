# Suricata DNS wire fixture

suricata-8.0.7-dns.jsonl is actual Suricata 8.0.7 output from two generated
Ethernet/IPv4/UDP packets: one A query and one successful A answer for a harmless
private lab name. Processing used the installed jasonish/suricata:8.0.7 image,
offline PCAP input, single runmode and Docker network none. No packets were sent.
Only DNS and final-flow rows are retained here; the unmodified complete output,
PCAP generator and engine log are in the local verification evidence directory.
This is test evidence, never a real training run or a claim that the four-VM lab ran.

The DNS wire id is 1000 on both messages. Suricata tx_id is 0 for the request and
1 for its response: those are engine transaction counters, not the DNS wire
transaction identifier. Correlate the full flow tuple, wire id, names and timing.
Both A output representations are present and must agree.

Format reference:
https://docs.suricata.io/en/suricata-8.0.7/upgrade/8.0-dns-logging-changes.html
