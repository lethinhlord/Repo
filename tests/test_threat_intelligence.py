from datetime import UTC, datetime, timedelta

import httpx2 as httpx
import pytest

from api.app.threat_intelligence import VirusTotalClient, lookup_threat_intelligence


def make_transport(status_code: int, payload: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == "unit-test-key"
        assert request.url.host == "www.virustotal.com"
        return httpx.Response(status_code, json=payload)

    return httpx.MockTransport(handler)


def test_virustotal_maps_detection_statistics_to_malicious_context() -> None:
    payload = {
        "data": {
            "type": "ip_address",
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 4,
                    "suspicious": 1,
                    "harmless": 55,
                    "undetected": 40,
                },
                "last_analysis_date": int(datetime.now(UTC).timestamp()),
            }
        }
    }
    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=make_transport(200, payload),
    )

    context = client.lookup("8.8.8.8")

    assert context.provider == "virustotal-v3"
    assert context.status == "MALICIOUS"
    assert context.available is True
    assert context.score == 0.05
    assert context.reason_code == "DETECTED"
    assert "5/100" in context.rationale


def test_virustotal_maps_zero_detection_statistics_to_clean_context() -> None:
    payload = {
        "data": {
            "type": "ip_address",
            "id": "8.8.4.4",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 30,
                },
                "last_analysis_date": int(datetime.now(UTC).timestamp()),
            }
        }
    }
    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=make_transport(200, payload),
    )

    context = client.lookup("8.8.4.4")

    assert context.status == "BENIGN"
    assert context.available is True
    assert context.score == 0.0


def test_too_few_analysis_votes_is_unknown_not_benign() -> None:
    payload = {
        "data": {
            "type": "ip_address",
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 2,
                    "undetected": 1,
                },
                "last_analysis_date": int(datetime.now(UTC).timestamp()),
            },
        }
    }
    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=make_transport(200, payload),
        minimum_engines=10,
    )

    context = client.lookup("8.8.8.8")

    assert context.status == "UNKNOWN"
    assert context.available is False
    assert context.score is None
    assert context.reason_code == "INSUFFICIENT_DATA"


def test_virustotal_rate_limit_degrades_to_unknown() -> None:
    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=make_transport(429, {"error": {"code": "QuotaExceededError"}}),
    )

    context = client.lookup("8.8.8.8")

    assert context.status == "UNKNOWN"
    assert context.available is False
    assert context.score is None
    assert context.reason_code == "RATE_LIMITED"
    assert "HTTP 429" in context.rationale


def test_virustotal_timeout_degrades_to_unknown() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=httpx.MockTransport(handler),
    )

    context = client.lookup("8.8.8.8")

    assert context.status == "UNKNOWN"
    assert context.available is False
    assert context.score is None
    assert context.reason_code == "TIMEOUT"
    assert "timed out" in context.rationale.lower()


def test_reserved_ip_is_not_disclosed_to_external_provider() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=httpx.MockTransport(handler),
    )

    context = client.lookup("203.0.113.66")

    assert called is False
    assert context.status == "UNKNOWN"
    assert context.available is False
    assert context.score is None
    assert context.reason_code == "NON_PUBLIC_INDICATOR"
    assert "public" in context.rationale.lower()


def test_mode_router_is_mock_by_default_and_disabled_fails_safe() -> None:
    mocked = lookup_threat_intelligence("203.0.113.66", mode="mock")
    disabled = lookup_threat_intelligence("8.8.8.8", mode="disabled")

    assert mocked.provider == "mock-ti-v2"
    assert mocked.status == "MALICIOUS"
    assert disabled.provider == "disabled"
    assert disabled.status == "UNKNOWN"
    assert disabled.score is None


def test_live_mode_without_api_key_fails_safe() -> None:
    context = lookup_threat_intelligence("8.8.8.8", mode="live", api_key=None)

    assert context.provider == "virustotal-v3"
    assert context.status == "UNKNOWN"
    assert context.reason_code == "NOT_CONFIGURED"
    assert "not configured" in context.rationale.lower()


@pytest.mark.parametrize(
    ("status_code", "reason_code"),
    [
        (401, "AUTH_ERROR"),
        (403, "AUTH_ERROR"),
        (404, "NOT_FOUND"),
        (503, "PROVIDER_UNAVAILABLE"),
    ],
)
def test_virustotal_http_errors_are_typed_unknown(
    status_code: int,
    reason_code: str,
) -> None:
    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=make_transport(status_code, {"error": {"code": "test"}}),
    )

    context = client.lookup("8.8.8.8")

    assert context.status == "UNKNOWN"
    assert context.available is False
    assert context.score is None
    assert context.reason_code == reason_code


def test_stale_virustotal_report_is_unknown() -> None:
    now = datetime(2026, 10, 8, tzinfo=UTC)
    payload = {
        "data": {
            "type": "ip_address",
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 30,
                },
                "last_analysis_date": int((now - timedelta(days=31)).timestamp()),
            },
        }
    }
    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=make_transport(200, payload),
        clock=lambda: now,
    )

    context = client.lookup("8.8.8.8")

    assert context.reason_code == "STALE_REPORT"
    assert context.score is None
    assert context.last_analysis_at is not None


def test_response_identity_mismatch_is_unknown() -> None:
    payload = {
        "data": {
            "type": "domain",
            "id": "different.example.org",
            "attributes": {
                "last_analysis_stats": {"malicious": 1},
                "last_analysis_date": int(datetime.now(UTC).timestamp()),
            },
        }
    }
    client = VirusTotalClient(
        api_key="unit-test-key",
        transport=make_transport(200, payload),
    )

    context = client.lookup("8.8.8.8")

    assert context.reason_code == "INVALID_RESPONSE"
    assert context.score is None
