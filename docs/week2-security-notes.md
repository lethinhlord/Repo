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
- Risk v2 renormalizes only over available signals and marks missing TI/asset as
  `review_required=true`.
- The n8n gate always emits `automation_state=SHADOW` and
  `strong_action_allowed=false`.
- API/network failures route to a degraded manual-review response.
- Protected assets always require review regardless of calculated risk.

## Lab exposure

FastAPI is published only on `127.0.0.1:8000` and remains reachable to n8n on
the private Docker network. n8n port 5678 is intentionally available to the VM
lab browser. `N8N_SECURE_COOKIE=false` and HTTP are acceptable only in this
isolated lab; use TLS, authenticated ingress and secure cookies before any
non-lab deployment.

## Secret-safe evidence

Screenshots may show service state, commands and responses, but must not show
`.env`, shell history containing a key, n8n credentials, authentication dialogs
or request headers. Before a commit, scan tracked content for common secret
patterns and inspect `git diff --cached`.
