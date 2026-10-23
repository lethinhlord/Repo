# Week 2 Security and Privacy Notes

## Trust boundaries

- Wazuh payloads and third-party VirusTotal replies are untrusted input and are
  validated with bounded Pydantic models.
- The VirusTotal base URL is fixed to HTTPS and redirects are disabled.
- The API key is accepted only from `VT_API_KEY`; it is never part of a request
  contract, workflow export, fixture, response or log.
- Reserved/private/test IP addresses and reserved domains are rejected before
  any external call. VirusTotal queries may disclose the submitted IoC to the
  provider and its community dataset.

## Fail-safe behavior

- Unknown TI and unknown assets carry `score=null`, not zero. Missingness cannot
  masquerade as benign context.
- Risk policy `risk-week2-v2` keeps the original denominator when TI or asset
  context is missing. Missing signals contribute zero and force
  `review_required=true`; this prevents the AI weight from increasing implicitly.
- `PARTIAL` features, an ineligible/uncertain model, malicious TI, unknown TI and
  protected assets all force review through explicit request fields and reasons.
- The n8n gate always emits `automation_state=SHADOW` and
  `strong_action_allowed=false`.
- API/network failures route to a degraded manual-review response.
- Protected assets always require review regardless of calculated risk.

## Durable response boundary

The `persist_incident_queue_review` playbook calls `POST /incidents/record`,
upserts the correlated incident in SQLite and inserts one durable
notification-outbox row per incident. `POST /notifications/dispatch` claims that row
under a bounded lease and records a delivery receipt. Lab mode uses the local
`audit-log` channel; webhook mode requires HTTPS and sends the stable incident ID as
an idempotency key. Failed delivery returns the row to `QUEUED` for retry. If the API
process stops after claiming a row, a later dispatcher may reclaim it only after
`NOTIFICATION_LEASE_SECONDS` (300 seconds by default). Delivery is therefore
at-least-once; webhook receivers must honor `Idempotency-Key` to suppress a duplicate
when a process stops after the remote system accepts a request but before SQLite stores
the receipt. A repeated source event with the identical decision is reported as
`duplicate`; reuse of that event ID with a different decision is rejected.

## Lab exposure

FastAPI is published only on `127.0.0.1:8000` and remains reachable to n8n on
the private Docker network. n8n binds to `127.0.0.1` by default. A four-VM lab
may set `N8N_BIND_ADDRESS` to the SOAR interface only after limiting TCP/5678 at
the host firewall to the Wazuh source and administrator workstation. Webhook
payloads require a 32-byte HMAC secret, a five-minute timestamp and a one-time
nonce. HMAC input uses RFC 8785 JCS canonical JSON so Python and n8n/JavaScript
produce the same bytes even when integer-valued JSON numbers are reserialized;
payloads are capped at 2 MB. Invalid, expired and replayed requests are
rejected before feature extraction. For any non-isolated network, terminate TLS
at a reverse proxy and set `N8N_PROTOCOL=https` and `N8N_SECURE_COOKIE=true`.

## Secret-safe evidence

Screenshots may show service state, commands and responses, but must not show
`.env`, shell history containing a key, n8n credentials, authentication dialogs
or request headers. Before a commit, scan tracked content for common secret
patterns and inspect `git diff --cached`.

## n8n audit interpretation

Run `docker compose exec -T n8n n8n audit` after deployment. The lab disables
community packages, templates, the public API, diagnostics and version notifications,
and pins n8n by version plus manifest digest. The webhook first passes a local header
shape gate and then API-side RFC 8785/HMAC, freshness, nonce-replay and rate-limit
verification. n8n still classifies built-in HTTP Request and Code nodes as generally
risky because those node types *can* execute dynamic behavior. In this workflow every
HTTP destination is a fixed `http://api:8000` endpoint on the private Compose network
and all Code-node programs are repository-controlled constants; user input never
selects a URL or executable program. Treat a future dynamic URL, expression-based code,
community node or Execute Command node as a release blocker.
