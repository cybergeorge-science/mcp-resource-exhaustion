"""Smoke tests for measure.benign_client.BenignClient on a fully synthetic
request_fn -- no MCP server, no network."""
import time

import pytest

from measure.benign_client import BenignClient, BenignClientConfig


def test_run_for_issues_approximately_rate_hz_times_duration_requests():
    call_count = {"n": 0}

    def fake_request():
        call_count["n"] += 1

    cfg = BenignClientConfig(rate_hz=20.0, duration_s=0.5, request_timeout_s=1.0)
    client = BenignClient(fake_request, cfg)
    recorder = client.run_for()

    expected = cfg.rate_hz * cfg.duration_s  # ~10 requests
    assert recorder.count == call_count["n"]
    # allow generous scheduling slack on a shared CI/dev box
    assert expected * 0.5 <= recorder.count <= expected * 1.5


def test_recorder_marks_exceptions_as_errors_not_crashes():
    def flaky_request():
        raise RuntimeError("simulated target failure")

    cfg = BenignClientConfig(rate_hz=50.0, duration_s=0.2, request_timeout_s=1.0)
    client = BenignClient(flaky_request, cfg)
    recorder = client.run_for()

    assert recorder.count > 0
    assert recorder.error_rate == 1.0


def test_slow_request_beyond_timeout_counts_as_error():
    def slow_request():
        time.sleep(0.05)

    cfg = BenignClientConfig(rate_hz=10.0, duration_s=0.15, request_timeout_s=0.01)
    client = BenignClient(slow_request, cfg)
    recorder = client.run_for()

    assert recorder.count > 0
    assert recorder.error_rate == 1.0  # every request exceeded the 10ms timeout


def test_start_background_and_stop_round_trip():
    call_count = {"n": 0}

    def fake_request():
        call_count["n"] += 1

    cfg = BenignClientConfig(rate_hz=20.0, duration_s=5.0, request_timeout_s=1.0)
    client = BenignClient(fake_request, cfg)
    client.start_background()
    time.sleep(0.3)
    client.stop()

    assert call_count["n"] > 0
    assert client.recorder.count == call_count["n"]
