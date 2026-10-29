from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from ml.clock_evidence import ClockPreflight

BASE = datetime(2026, 10, 28, tzinfo=UTC)


def evidence():
    samples = {}
    for host, second in zip(
        ("controller", "target", "wazuh", "sensor", "attacker"), (0, 2, 3, 5, 6), strict=True
    ):
        instant = BASE + timedelta(seconds=second)
        samples[host] = {
            "controller_before": instant,
            "remote_utc": instant,
            "controller_after": instant,
        }
    return {"captured_at": BASE + timedelta(seconds=7), "measurements": samples}


def test_sequential_synchronized_samples_pass():
    model = ClockPreflight(**evidence())
    assert model.attacker_utc == BASE + timedelta(seconds=6)


@pytest.mark.parametrize(
    "change", ["drift", "rtt", "reverse", "missing", "naive", "stale", "inconsistent"]
)
def test_invalid_measurements_fail(change):
    data = evidence()
    samples = data["measurements"]
    if change == "drift":
        samples["target"]["remote_utc"] += timedelta(seconds=6)
    elif change == "rtt":
        samples["target"]["controller_after"] += timedelta(seconds=5)
    elif change == "reverse":
        samples["target"]["controller_after"] -= timedelta(seconds=1)
    elif change == "missing":
        del samples["target"]
    elif change == "naive":
        samples["target"]["remote_utc"] = BASE.replace(tzinfo=None)
    elif change == "stale":
        data["captured_at"] += timedelta(seconds=121)
    else:
        samples["controller"]["remote_utc"] += timedelta(seconds=1)
    with pytest.raises(ValidationError):
        ClockPreflight(**data)


def test_uncertain_roundtrip_must_not_hide_skew():
    data = evidence()
    data["captured_at"] = BASE + timedelta(seconds=12)
    data["measurements"]["target"] = {
        "controller_before": BASE + timedelta(seconds=5),
        "controller_after": BASE + timedelta(seconds=9),
        "remote_utc": BASE + timedelta(seconds=11),
    }
    with pytest.raises(ValidationError):
        ClockPreflight(**data)


def test_opposite_offsets_with_nonzero_roundtrips():
    data = evidence()
    for host, offset in (("target", 2), ("sensor", -2)):
        sample = data["measurements"][host]
        sample["controller_after"] += timedelta(seconds=2)
        sample["remote_utc"] += timedelta(seconds=offset + 1)
    data["captured_at"] += timedelta(seconds=2)
    with pytest.raises(ValidationError):
        ClockPreflight(**data)


def test_nonzero_roundtrip_with_bounded_uncertainty_passes():
    data = evidence()
    sample = data["measurements"]["target"]
    sample["controller_after"] += timedelta(seconds=2)
    sample["remote_utc"] += timedelta(seconds=1)
    model = ClockPreflight(**data)
    assert model.target_utc == sample["remote_utc"]


@pytest.mark.parametrize("contents", [None, "{bad", "{}"])
def test_cli_input_errors_are_concise(tmp_path, contents):
    import subprocess
    import sys

    path = tmp_path / "measurements.json"
    if contents is not None:
        path.write_text(contents, encoding="utf-8")
    output = tmp_path / "clock.yaml"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.build_clock_preflight",
            "--measurements",
            str(path),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_measured_yaml_reload_and_legacy_parse():
    import yaml

    model = ClockPreflight(**evidence())
    reloaded = ClockPreflight.model_validate(
        yaml.safe_load(yaml.safe_dump(model.model_dump(mode="json")))
    )
    assert reloaded == model
    legacy = model.model_dump(exclude={"measurements", "maximum_roundtrip_seconds"})
    for host in ("controller", "target", "wazuh", "sensor", "attacker"):
        legacy[f"{host}_utc"] = BASE
    assert ClockPreflight.model_validate(legacy).measurements is None
