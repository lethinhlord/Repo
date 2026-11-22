"""Closed registry of reviewed feature contracts, never arbitrary package schemas."""
from __future__ import annotations

import json
import math
from pathlib import Path

SCHEMA_FILES = {
    "features-v3": "feature_schema.json",
    "features-v4-stream-v1": "feature_schema_stream.json",
    "features-v5-http-v1": "feature_schema_http.json",
}


def registered_schema(version: str) -> dict:
    if not isinstance(version, str) or version not in SCHEMA_FILES:
        raise ValueError("unsupported feature profile")
    return json.loads(Path(__file__).with_name(SCHEMA_FILES[version]).read_text(encoding="utf-8"))


def validate_stream_values(features: dict, schema: dict) -> None:
    if set(features) != set(schema["required"]):
        raise ValueError("stream feature schema requires exactly the declared complete vector")
    for name, value in features.items():
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not schema["properties"][name]["minimum"] <= value
                <= schema["properties"][name]["maximum"]):
            raise ValueError(f"{name} violates the stream feature schema bounds")
