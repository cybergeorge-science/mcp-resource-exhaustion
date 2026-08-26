"""Smoke tests for measure.latency.LatencyRecorder on synthetic data --
no MCP server, no network, no subprocess."""
import math

from measure.latency import LatencyRecorder


def test_empty_recorder_returns_nan_percentiles_and_zero_error_rate():
    rec = LatencyRecorder()
    assert rec.count == 0
    assert rec.error_rate == 0.0
    assert math.isnan(rec.percentile(50))


def test_percentiles_match_known_distribution():
    rec = LatencyRecorder()
    # 0..100 ms in 1ms steps (101 samples) -> exact percentile boundaries.
    for i in range(101):
        rec.record(float(i))
    assert rec.percentile(50) == 50.0
    assert rec.percentile(95) == 95.0
    assert rec.percentile(99) == 99.0
    assert rec.percentile(0) == 0.0
    assert rec.percentile(100) == 100.0


def test_single_sample_percentile_is_that_sample():
    rec = LatencyRecorder()
    rec.record(42.0)
    assert rec.percentile(50) == 42.0
    assert rec.percentile(99) == 42.0


def test_error_rate_and_count_track_errors_separately_from_latency_samples():
    rec = LatencyRecorder()
    for _ in range(8):
        rec.record(10.0, error=False)
    for _ in range(2):
        rec.record(0.0, error=True)
    assert rec.count == 10
    assert rec.error_count == 2
    assert rec.error_rate == 0.2
    # errored calls must not pollute the latency percentile computation
    assert rec.percentile(50) == 10.0


def test_summary_contains_all_table6_latency_fields():
    rec = LatencyRecorder()
    rec.record(5.0)
    rec.record(15.0, error=True)
    summary = rec.summary()
    for key in ("lat_p50_ms", "lat_p95_ms", "lat_p99_ms", "error_rate", "n"):
        assert key in summary
    assert summary["n"] == 2
    assert summary["error_rate"] == 0.5


def test_reset_clears_all_state():
    rec = LatencyRecorder()
    rec.record(5.0)
    rec.record(1.0, error=True)
    rec.reset()
    assert rec.count == 0
    assert rec.error_rate == 0.0
    assert math.isnan(rec.percentile(50))
