"""Tests for common/synth_model.py: predict_cell consistency (P1.2)."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from common.schema import Record  # noqa: E402
from common import synth_model as sm  # noqa: E402


def _anchor(mit):
    # v1: mem channel, http/python, concurrency=8, anchor load index 3 (10 MB)
    return Record(
        vector="v1_oversized_body", transport="http", sdk="python",
        load_level=3, concurrency=8, mitigation=mit,
        peak_rss_mb=(69.0 if mit else 260.0), mean_cpu_pct=(4.0 if mit else 6.0),
        lat_p50_ms=(5.0 if mit else 5.0), lat_p95_ms=(20.0 if mit else 10.0),
        lat_p99_ms=(25.0 if mit else 12.0), error_rate=0.0,
        ts_start=1000.0, ts_end=1002.0, is_synthetic=False,
        recovery_s=(0.2 if mit else 8.0), amplification=(0.02 if mit else 2.4),
    )


def test_predict_cell_reproduces_anchor_at_ratio_one():
    off, on = _anchor(False), _anchor(True)
    pred = sm.predict_cell("v1_oversized_body", off, on,
                           load_level=3, concurrency=8, mitigation=False)
    # ratios are 1 -> the model returns the anchor's own values
    assert abs(pred["peak_rss_mb"] - 260.0) < 0.5
    assert abs(pred["mean_cpu_pct"] - 6.0) < 0.1
    assert abs(pred["lat_p95_ms"] - 10.0) < 0.1
    assert pred["error_rate"] == 0.0


def test_predict_cell_matches_sweep_mean_at_second_point():
    off, on = _anchor(False), _anchor(True)
    pred = sm.predict_cell("v1_oversized_body", off, on,
                           load_level=4, concurrency=8, mitigation=False)
    sweep = sm.generate_for_vector("v1_oversized_body", off, on)
    cell = [r for r in sweep if r.transport == "http" and r.sdk == "python"
            and r.load_level == 4 and r.concurrency == 8 and not r.mitigation]
    assert cell, "sweep should contain the 2nd-anchor cell"
    mean_peak = sum(r.peak_rss_mb for r in cell) / len(cell)
    # predict_cell (deterministic) must be within jitter range (+/-6%) of the
    # sweep replicate mean -> confirms shared formulas, no drift
    assert abs(pred["peak_rss_mb"] - mean_peak) / mean_peak < 0.06


def test_generate_for_vector_grid_size():
    off, on = _anchor(False), _anchor(True)
    sweep = sm.generate_for_vector("v1_oversized_body", off, on)
    # v1 applicable transports {http,stdio} x 2 sdk x 5 load x 4 conc x 2 mit
    # x 5 reps, minus the skipped real anchor cell (both OFF and ON) x 5 reps
    expected = (2 * 2 * 5 * 4 * 2 * sm.N_REPS) - (2 * sm.N_REPS)
    assert len(sweep) == expected
    assert all(r.is_synthetic for r in sweep)
