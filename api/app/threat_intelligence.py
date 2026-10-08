import ipaddress
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import httpx2 as httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field

from api.app.contracts import ThreatIntelligenceResult
from api.app.mock_services import lookup_ti_mock

_DOMAIN_RE = re.compile(
    r"(?=^.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
_RESERVED_SUFFIXES = (".example", ".invalid", ".localhost", ".test")
_Provider = Literal["mock-ti-v2", "virustotal-v3", "disabled"]


class _VirusTotalSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    minimum_engines: int = Field(ge=1, le=1000)
    max_report_age_days: int = Field(ge=1, le=3650)
    timeout_seconds: float = Field(ge=1.0, le=15.0)


class ThreatIntelligencePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: Literal["ti-week2-v1"]
    virustotal: _VirusTotalSettings

    @classmethod
    def load(cls, path: Path) -> "ThreatIntelligencePolicy":
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


class _AnalysisStats(BaseModel):
    model_config = ConfigDict(extra="ignore")

    malicious: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)
    harmless: int = Field(default=0, ge=0)
    undetected: int = Field(default=0, ge=0)
    timeout: int = Field(default=0, ge=0)


class _Attributes(BaseModel):
    model_config = ConfigDict(extra="ignore")

    last_analysis_stats: _AnalysisStats
    last_analysis_date: int = Field(gt=0)


class _VirusTotalData(BaseModel):
    model_config = ConfigDict(extra="ignore")

    type: Literal["ip_address", "domain"]
    id: str
    attributes: _Attributes


class _VirusTotalEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data: _VirusTotalData


def _indicator_kind(indicator: str) -> Literal["ip_addresses", "domains"] | None:
    value = indicator.strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        lowered = value.lower().rstrip(".")
        if lowered.endswith(_RESERVED_SUFFIXES) or not _DOMAIN_RE.fullmatch(lowered):
            return None
        return "domains"
    return "ip_addresses" if address.is_global else None


def _unknown(
    provider: _Provider,
    indicator: str | None,
    reason_code: str,
    rationale: str,
) -> ThreatIntelligenceResult:
    return ThreatIntelligenceResult(
        provider=provider,
        indicator=indicator,
        status="UNKNOWN",
        available=False,
        score=None,
        reason_code=reason_code,
        rationale=rationale,
    )


class VirusTotalClient:
    """Fail-safe VirusTotal v3 adapter with strict response validation."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: float = 5.0,
        minimum_engines: int = 10,
        max_report_age_days: int = 30,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout = min(max(float(timeout_seconds), 1.0), 15.0)
        self._minimum_engines = max(int(minimum_engines), 1)
        self._max_report_age = timedelta(days=max(int(max_report_age_days), 1))
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))

    def lookup(self, indicator: str | None) -> ThreatIntelligenceResult:
        if not indicator:
            return _unknown(
                "virustotal-v3", indicator, "NO_INDICATOR", "No indicator was supplied."
            )
        normalized = indicator.strip().lower().rstrip(".")
        kind = _indicator_kind(normalized)
        if kind is None:
            return _unknown(
                "virustotal-v3",
                indicator,
                "NON_PUBLIC_INDICATOR",
                "Indicator is not public; no external query was sent.",
            )

        url = f"https://www.virustotal.com/api/v3/{kind}/{quote(normalized, safe='')}"
        try:
            with httpx.Client(
                timeout=self._timeout,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = client.get(url, headers={"x-apikey": self._api_key})
        except httpx.TimeoutException:
            return _unknown(
                "virustotal-v3", indicator, "TIMEOUT", "VirusTotal request timed out."
            )
        except httpx.HTTPError:
            return _unknown(
                "virustotal-v3",
                indicator,
                "PROVIDER_UNAVAILABLE",
                "VirusTotal is unavailable; enrichment is UNKNOWN.",
            )

        if response.status_code != 200:
            reason_code = {
                401: "AUTH_ERROR",
                403: "AUTH_ERROR",
                404: "NOT_FOUND",
                429: "RATE_LIMITED",
            }.get(response.status_code, "PROVIDER_UNAVAILABLE")
            return _unknown(
                "virustotal-v3",
                indicator,
                reason_code,
                f"VirusTotal returned HTTP {response.status_code}; enrichment is UNKNOWN.",
            )

        try:
            envelope = _VirusTotalEnvelope.model_validate(response.json())
            expected_type = "ip_address" if kind == "ip_addresses" else "domain"
            if envelope.data.type != expected_type or envelope.data.id.lower() != normalized:
                raise ValueError("VirusTotal response identity mismatch")
            observed_at = datetime.fromtimestamp(
                envelope.data.attributes.last_analysis_date,
                tz=UTC,
            )
            if self._clock() - observed_at > self._max_report_age:
                result = _unknown(
                    "virustotal-v3",
                    indicator,
                    "STALE_REPORT",
                    "VirusTotal report is stale; enrichment is UNKNOWN.",
                )
                return result.model_copy(update={"last_analysis_at": observed_at})
            stats = envelope.data.attributes.last_analysis_stats
            detections = stats.malicious + stats.suspicious
            all_votes = detections + stats.harmless + stats.undetected
            evaluated = detections + stats.harmless
            if detections > 0 and all_votes > 0:
                score = round(min(detections / all_votes, 1.0), 6)
                return ThreatIntelligenceResult(
                    provider="virustotal-v3",
                    indicator=indicator,
                    status="MALICIOUS",
                    available=True,
                    score=score,
                    reason_code="DETECTED",
                    rationale=(
                        f"VirusTotal detections: {detections}/{all_votes} "
                        "(malicious plus suspicious votes)."
                    ),
                    detections=detections,
                    total_votes=all_votes,
                    last_analysis_at=observed_at,
                )
            if evaluated >= self._minimum_engines and stats.harmless >= self._minimum_engines:
                return ThreatIntelligenceResult(
                    provider="virustotal-v3",
                    indicator=indicator,
                    status="BENIGN",
                    available=True,
                    score=0.0,
                    reason_code="NO_DETECTIONS",
                    rationale=(
                        "VirusTotal has no malicious or suspicious detections and "
                        f"{stats.harmless} harmless votes."
                    ),
                    detections=0,
                    total_votes=all_votes,
                    last_analysis_at=observed_at,
                )
            return _unknown(
                "virustotal-v3",
                indicator,
                "INSUFFICIENT_DATA",
                "VirusTotal has too few affirmative analysis votes; enrichment is UNKNOWN.",
            )
        except (KeyError, TypeError, ValueError):
            return _unknown(
                "virustotal-v3",
                indicator,
                "INVALID_RESPONSE",
                "VirusTotal returned an invalid response; enrichment is UNKNOWN.",
            )


def lookup_threat_intelligence(
    indicator: str | None,
    *,
    mode: str = "mock",
    api_key: str | None = None,
    timeout_seconds: float = 5.0,
    minimum_engines: int = 10,
    max_report_age_days: int = 30,
) -> ThreatIntelligenceResult:
    normalized_mode = mode.strip().lower()
    if normalized_mode == "mock":
        legacy = lookup_ti_mock(indicator)
        if legacy.status == "MALICIOUS":
            return ThreatIntelligenceResult(
                provider="mock-ti-v2",
                indicator=indicator,
                status="MALICIOUS",
                available=True,
                score=legacy.score,
                reason_code="DETECTED",
                rationale=legacy.rationale,
            )
        if legacy.status == "CLEAN":
            return ThreatIntelligenceResult(
                provider="mock-ti-v2",
                indicator=indicator,
                status="BENIGN",
                available=True,
                score=0.0,
                reason_code="NO_DETECTIONS",
                rationale=legacy.rationale,
            )
        return _unknown(
            "mock-ti-v2", indicator, "INSUFFICIENT_DATA", legacy.rationale
        )
    if normalized_mode == "disabled":
        return _unknown(
            "disabled",
            indicator,
            "DISABLED",
            "Threat-intelligence lookup is disabled.",
        )
    if normalized_mode != "live":
        return _unknown(
            "disabled",
            indicator,
            "INVALID_MODE",
            "Invalid VT_MODE; enrichment is disabled.",
        )
    if not api_key:
        return _unknown(
            "virustotal-v3",
            indicator,
            "NOT_CONFIGURED",
            "VirusTotal live mode is not configured with an API key.",
        )
    return VirusTotalClient(
        api_key=api_key,
        timeout_seconds=timeout_seconds,
        minimum_engines=minimum_engines,
        max_report_age_days=max_report_age_days,
    ).lookup(indicator)
