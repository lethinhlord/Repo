from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class NotificationDeliveryError(RuntimeError):
    pass


def _validate_webhook_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    loopback_http = parsed.scheme == "http" and parsed.hostname in {
        "127.0.0.1",
        "localhost",
    }
    if parsed.scheme != "https" and not loopback_http:
        raise NotificationDeliveryError(
            "notification webhook must use HTTPS (loopback HTTP is allowed for tests)"
        )


def deliver_notification(
    incident_id: str,
    notification: str,
    *,
    mode: str,
    webhook_url: str | None,
    timeout_seconds: float,
    notification_key: str | None = None,
) -> str:
    normalized = mode.strip().lower()
    if normalized == "log":
        return "audit-log"
    if normalized != "webhook":
        raise NotificationDeliveryError("NOTIFICATION_MODE must be log or webhook")
    if not webhook_url:
        raise NotificationDeliveryError("NOTIFICATION_WEBHOOK_URL is required in webhook mode")
    _validate_webhook_url(webhook_url)
    body = json.dumps(
        {"incident_id": incident_id, "notification": notification},
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(  # noqa: S310
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Idempotency-Key": notification_key or incident_id,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            if not 200 <= response.status < 300:
                raise NotificationDeliveryError(
                    f"notification webhook returned HTTP {response.status}"
                )
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise NotificationDeliveryError(f"notification webhook failed: {exc}") from exc
    return "webhook"
