from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from api.app.contracts import AssetContext


class _AssetEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1, max_length=128)
    criticality: int | None = Field(default=None, ge=1, le=5)
    protected: bool


class _AssetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: str
    default: _AssetEntry
    assets: dict[str, _AssetEntry]

    @model_validator(mode="after")
    def validate_defaults_and_assets(self) -> "_AssetInventory":
        if self.default.criticality is not None or not self.default.protected:
            raise ValueError("default asset context must be unscored and protected")
        if any(entry.criticality is None for entry in self.assets.values()):
            raise ValueError("inventory assets require criticality")
        return self


def _normalize_asset_id(asset_id: str) -> str:
    normalized = asset_id.strip().casefold()
    if not normalized or len(normalized) > 128:
        raise ValueError("asset_id must contain 1 to 128 characters")
    return normalized


class AssetContextRepository:
    def __init__(self, inventory_path: Path) -> None:
        document = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
        self._inventory = _AssetInventory.model_validate(document)
        if self._inventory.revision != "asset-context-v1":
            raise ValueError("unsupported asset context revision")
        self._assets: dict[str, tuple[str, _AssetEntry]] = {}
        for canonical_id, entry in self._inventory.assets.items():
            normalized = _normalize_asset_id(canonical_id)
            if normalized in self._assets:
                raise ValueError("asset inventory contains a normalized-key collision")
            self._assets[normalized] = (canonical_id, entry)

    def get(self, asset_id: str) -> AssetContext:
        normalized = _normalize_asset_id(asset_id)
        found = self._assets.get(normalized)
        if found is None:
            entry = self._inventory.default
            return AssetContext(
                asset_id=asset_id.strip(),
                role=entry.role,
                criticality=None,
                protected=True,
                risk_score=None,
                source="default",
                status="UNKNOWN",
                review_required=True,
            )
        canonical_id, entry = found
        assert entry.criticality is not None
        return AssetContext(
            asset_id=canonical_id,
            role=entry.role,
            criticality=entry.criticality,
            protected=entry.protected,
            risk_score=entry.criticality / 5.0,
            source="inventory",
            status="FOUND",
            review_required=entry.protected,
        )
