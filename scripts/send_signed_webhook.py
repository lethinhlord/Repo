from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.app.webhook_auth import sign_payload  # noqa: E402 - root is bootstrapped above


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a signed Wazuh webhook fixture")
    parser.add_argument("payload", type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-http-status", type=int, default=200)
    args = parser.parse_args()

    secret = os.environ.get("WAZUH_WEBHOOK_SECRET", "")
    if len(secret.encode()) < 32:
        raise SystemExit("WAZUH_WEBHOOK_SECRET must contain at least 32 bytes")
    payload = json.loads(args.payload.read_text(encoding="utf-8"))
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    signature = sign_payload(
        secret,
        timestamp=timestamp,
        nonce=nonce,
        payload=payload,
    )
    request = urllib.request.Request(
        args.url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Content-Type": "application/json",
            "X-SOAR-Timestamp": str(timestamp),
            "X-SOAR-Nonce": nonce,
            "X-SOAR-Signature": signature,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read()
        status = exc.code
    args.output.write_bytes(body)
    if status != args.expect_http_status:
        raise SystemExit(
            f"webhook returned HTTP {status}, expected {args.expect_http_status}; "
            "response saved"
        )


if __name__ == "__main__":
    main()
