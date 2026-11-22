from datetime import UTC, datetime, timedelta

import pytest

from ml.behavior_features import NetworkObservation
from ml.stream_features import StreamObservation, derive_stream_features

START = datetime(2026, 1, 1, tzinfo=UTC)


def observation(seconds, *, peer="192.0.2.10", port=443, image="curl.exe", guid="p1", dns=None):
    return StreamObservation(
        NetworkObservation(START + timedelta(seconds=seconds), peer, port, dns,
                           protocol=None if dns else "tcp"),
        process_instance=guid, process_image=image,
    )


def test_background_dns_does_not_change_tcp_conversation_timing():
    tcp = [observation(i * 2, guid=f"curl-{i}") for i in range(6)]
    before = derive_stream_features(tcp)
    after = derive_stream_features([
        *tcp, observation(95, peer="windows.example", port=53,
                          image="svchost.exe", dns="windows.example"),
    ])
    assert after["dominant_tcp_periodicity_score"] == before["dominant_tcp_periodicity_score"] == 1
    assert after["dominant_tcp_mean_interval_seconds"] == 2
    assert after["tcp_connection_count"] == 6
    assert after["dns_observation_fraction"] == pytest.approx(1 / 7, abs=1e-6)
    assert after["network_process_count"] == 7


def test_separate_process_instances_of_same_image_form_one_conversation():
    result = derive_stream_features([observation(i * 4, guid=str(i)) for i in range(4)])
    assert result["tcp_conversation_count"] == 1
    assert result["network_process_count"] == 4
    assert result["dominant_tcp_observation_count"] == 4


def test_unrelated_process_or_destination_does_not_enter_dominant_timing():
    result = derive_stream_features([
        observation(0), observation(10), observation(20),
        observation(9, image="browser.exe", guid="browser"), observation(19, peer="192.0.2.99"),
    ])
    assert result["tcp_conversation_count"] == 3
    assert result["dominant_tcp_observation_count"] == 3
    assert result["dominant_tcp_mean_interval_seconds"] == 10
    assert result["dominant_tcp_share"] == pytest.approx(.6)


def test_no_tcp_has_explicit_unavailable_timing_and_dns_only_mode():
    result = derive_stream_features([observation(5, dns="one.example")])
    assert result["tcp_connection_count"] == 0
    assert result["dns_only_window"] == 1
    for name in ("dominant_tcp_timing_available", "dominant_tcp_periodicity_available",
                 "dominant_tcp_order_available", "dominant_tcp_context_known"):
        assert result[name] == 0


def test_one_connection_is_not_measured_perfect_periodicity():
    result = derive_stream_features([observation(0)])
    assert result["dominant_tcp_observation_count"] == 1
    assert result["dominant_tcp_timing_available"] == 0
    assert result["dominant_tcp_periodicity_available"] == 0
    assert result["dominant_tcp_periodicity_score"] == 0


def test_interval_order_distinguishes_equal_mean_and_cv():
    alternating = derive_stream_features([observation(t) for t in (0, 1, 10, 11, 20)])
    clustered = derive_stream_features([observation(t) for t in (0, 1, 2, 11, 20)])
    assert (alternating["dominant_tcp_mean_interval_seconds"]
            == clustered["dominant_tcp_mean_interval_seconds"])
    assert alternating["dominant_tcp_interval_cv"] == clustered["dominant_tcp_interval_cv"]
    assert alternating["dominant_tcp_interval_alternation"] == 1
    assert clustered["dominant_tcp_interval_alternation"] == pytest.approx(1 / 3, abs=1e-6)


def test_renaming_guids_and_input_order_cannot_change_feature_values():
    a = [observation(i * 3, guid=f"id-{i}") for i in range(5)]
    b = [observation(i * 3, guid=f"unrelated-{i}") for i in reversed(range(5))]
    assert derive_stream_features(a) == derive_stream_features(b)


def test_tied_dominant_stream_is_explicitly_ambiguous():
    result = derive_stream_features([
        observation(0), observation(5),
        observation(0, peer="192.0.2.99"), observation(12, peer="192.0.2.99"),
    ])
    assert result["dominant_tcp_unique"] == 0
    assert result["dominant_tcp_context_known"] == 0


def test_missing_process_identity_is_not_a_verified_conversation():
    with pytest.raises(ValueError, match="process identity"):
        derive_stream_features([observation(0, image="", guid="")])


def test_same_basename_at_different_executable_paths_is_not_one_conversation():
    result = derive_stream_features([
        observation(0, image=r"C:\Windows\System32\curl.exe", guid="system"),
        observation(5, image=r"C:\Windows\System32\curl.exe", guid="system"),
        observation(0, image=r"C:\Temp\curl.exe", guid="other"),
        observation(12, image=r"C:\Temp\curl.exe", guid="other"),
    ])
    assert result['tcp_conversation_count'] == 2
    assert result['dominant_tcp_unique'] == 0


def test_windows_image_case_and_slash_adapter_changes_preserve_conversation():
    result = derive_stream_features([
        observation(0, image=r"C:\Windows\System32\curl.exe", guid="one"),
        observation(5, image="c:/WINDOWS/system32/CURL.EXE", guid="two"),
    ])
    assert result['tcp_conversation_count'] == 1
