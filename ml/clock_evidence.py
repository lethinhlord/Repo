from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

HOSTS = ("controller", "target", "wazuh", "sensor", "attacker")


class ClockMeasurement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    controller_before: datetime
    remote_utc: datetime
    controller_after: datetime


class ClockPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid")

    captured_at: datetime
    controller_utc: datetime
    target_utc: datetime
    wazuh_utc: datetime
    sensor_utc: datetime
    attacker_utc: datetime
    maximum_skew_seconds: float = Field(default=5.0, gt=0, le=10)
    maximum_capture_age_seconds: float = Field(default=120.0, gt=0, le=300)
    measurements: dict[str, ClockMeasurement] | None = None
    maximum_roundtrip_seconds: float = Field(default=4.0, gt=0, le=4)

    @model_validator(mode="before")
    @classmethod
    def populate_raw_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict) or value.get("measurements") is None:
            return value
        data = dict(value)
        samples = data["measurements"]
        if isinstance(samples, dict):
            for host in HOSTS:
                sample = samples.get(host)
                raw = (
                    sample.get("remote_utc")
                    if isinstance(sample, dict)
                    else getattr(sample, "remote_utc", None)
                )
                if raw is not None:
                    data.setdefault(f"{host}_utc", raw)
        return data

    @model_validator(mode="after")
    def validate_clock_skew(self) -> ClockPreflight:
        values = [getattr(self, f"{host}_utc") for host in HOSTS]
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("captured_at must include a timezone")
        if any(v.tzinfo is None or v.utcoffset() is None for v in values):
            raise ValueError("clock preflight timestamps must include a timezone")
        if self.measurements is None:
            span = (max(values) - min(values)).total_seconds()
            if span > self.maximum_skew_seconds:
                raise ValueError(
                    f"VM clock skew {span:.3f}s exceeds {self.maximum_skew_seconds:.3f}s"
                )
            age = (self.captured_at - min(values)).total_seconds()
            if age < -1 or age > self.maximum_capture_age_seconds:
                raise ValueError("clock preflight measurements are stale or captured in the future")
            return self
        if set(self.measurements) != set(HOSTS):
            raise ValueError("measurements must contain exactly the five required hosts")
        if self.captured_at.utcoffset() != timedelta(0):
            raise ValueError("captured_at must be UTC")
        intervals = [(0.0, 0.0)]
        for host, sample in self.measurements.items():
            times = (sample.controller_before, sample.remote_utc, sample.controller_after)
            if any(t.tzinfo is None or t.utcoffset() != timedelta(0) for t in times):
                raise ValueError("measurements must use UTC timestamps")
            if getattr(self, f"{host}_utc") != sample.remote_utc:
                raise ValueError("raw timestamps do not match measurements")
            rtt = (sample.controller_after - sample.controller_before).total_seconds()
            if rtt < 0 or rtt > self.maximum_roundtrip_seconds:
                raise ValueError("invalid clock measurement round trip")
            age = (self.captured_at - sample.controller_before).total_seconds()
            if age > self.maximum_capture_age_seconds or self.captured_at < sample.controller_after:
                raise ValueError("clock measurement is stale or captured in the future")
            if (
                host in ("controller", "wazuh")
                and not sample.controller_before <= sample.remote_utc <= sample.controller_after
            ):
                raise ValueError("local clock reading must fall within controller interval")
            if host not in ("controller", "wazuh"):
                intervals.append(
                    (
                        (sample.remote_utc - sample.controller_after).total_seconds(),
                        (sample.remote_utc - sample.controller_before).total_seconds(),
                    )
                )
        if any(
            upper - other_lower > self.maximum_skew_seconds
            for index, (_, upper) in enumerate(intervals)
            for other_index, (other_lower, _) in enumerate(intervals)
            if index != other_index
        ):
            raise ValueError("VM clock skew could exceed maximum; resample with lower RTT")
        return self
