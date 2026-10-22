from __future__ import annotations

import argparse
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

from api.app.webhook_auth import sign_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a signed Wazuh webhook fixture")
    parser.add_argument("payload", type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    except urllib.error.HTTPError as exc:
        body = exc.read()
        args.output.write_bytes(body)
        raise SystemExit(f"webhook returned HTTP {exc.code}; response saved") from exc
    args.output.write_bytes(body)


if __name__ == "__main__":
    main()
