from pathlib import Path

import pytest

from api.app.asset_context import AssetContextRepository

ROOT = Path(__file__).resolve().parents[1]


def repository() -> AssetContextRepository:
    return AssetContextRepository(ROOT / "config" / "asset-context.yaml")


def test_known_workstation_context_is_loaded_from_versioned_inventory() -> None:
    context = repository().get("WIN11-01")

    assert context.asset_id == "WIN11-01"
    assert context.role == "workstation"
    assert context.criticality == 3
    assert context.protected is False
    assert context.risk_score == 0.6
    assert context.source == "inventory"
    assert context.status == "FOUND"
    assert context.review_required is False
    assert context.context_revision == "asset-context-v1"


def test_security_platform_is_critical_and_protected() -> None:
    context = repository().get("SOC-CORE")

    assert context.criticality == 5
    assert context.protected is True
    assert context.risk_score == 1.0
    assert context.review_required is True


def test_collection_target_resolves_to_canonical_inventory() -> None:
    context = repository().get("WIN11-TARGET")

    assert context.status == "FOUND"
    assert context.asset_id == "WIN11-TARGET"
    assert context.role == "workstation"
    assert context.review_required is False


def test_unknown_asset_uses_conservative_review_required_default() -> None:
    context = repository().get("unregistered-host")

    assert context.criticality is None
    assert context.protected is True
    assert context.risk_score is None
    assert context.source == "default"
    assert context.status == "UNKNOWN"
    assert context.review_required is True


def test_asset_lookup_is_case_and_whitespace_insensitive() -> None:
    context = repository().get("  win11-01  ")

    assert context.asset_id == "WIN11-01"
    assert context.status == "FOUND"


def test_normalized_inventory_collision_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "assets.yaml"
    path.write_text(
        """revision: asset-context-v1
default: {role: unknown, criticality: null, protected: true}
assets:
  WIN11-01: {role: workstation, criticality: 3, protected: false}
  win11-01: {role: workstation, criticality: 4, protected: false}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="collision"):
        AssetContextRepository(path)
