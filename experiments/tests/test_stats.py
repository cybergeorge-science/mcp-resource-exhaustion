"""Unit tests for common/stats.py (P1.1 replication statistics)."""
import math
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from common import stats  # noqa: E402


def test_t_critical_table_and_fallback():
    assert stats.t_critical_95(9) == 2.262
    assert stats.t_critical_95(1) == 12.706
    assert stats.t_critical_95(30) == 2.042
    assert stats.t_critical_95(40) == 1.96  # df>30 -> normal


def test_mean_sd_ci_basic():
    xs = [2, 4, 4, 4, 5, 5, 7, 9]
    r = stats.mean_sd_ci(xs)
    assert r["n"] == 8
    assert abs(r["mean"] - 5.0) < 1e-9
    # sample sd = sqrt(32/7) = 2.138...
    assert abs(r["sd"] - math.sqrt(32 / 7)) < 1e-9
    assert r["ci_lo"] < r["mean"] < r["ci_hi"]
    assert r["half_width"] > 0


def test_mean_sd_ci_edge_cases():
    assert stats.mean_sd_ci([])["n"] == 0
    one = stats.mean_sd_ci([3.0])
    assert one["n"] == 1 and one["sd"] == 0.0 and one["half_width"] == 0.0
    assert one["ci_lo"] == one["ci_hi"] == 3.0


def test_median_iqr():
    r = stats.median_iqr([1, 2, 3, 4, 5, 6, 7, 8, 9])
    assert r["median"] == 5
    assert r["q1"] == 3 and r["q3"] == 7
    assert r["iqr"] == 4


def test_iqr_outliers_flags_extreme():
    xs = [10, 11, 12, 11, 10, 12, 100]  # 100 is an outlier
    idx = stats.iqr_outliers(xs)
    assert 6 in idx
    # a clean set has none
    assert stats.iqr_outliers([10, 11, 12, 11, 10, 12]) == []


def test_mann_whitney_fully_separated():
    a = [1, 2, 3, 4, 5]
    b = [6, 7, 8, 9, 10]
    r = stats.mann_whitney_u(a, b)
    assert r["U"] == 0.0
    assert r["p_value"] < 0.05
    assert abs(abs(r["rank_biserial"]) - 1.0) < 1e-9


def test_mann_whitney_identical_groups():
    r = stats.mann_whitney_u([1, 2, 3], [1, 2, 3])
    # symmetric -> U at the mean, no significant difference
    assert r["p_value"] > 0.5
    assert abs(r["rank_biserial"]) < 1e-9


def test_summarize_cell_filters_warmup_and_synthetic():
    rows = [
        {"is_synthetic": False, "rep_index": -1, "peak_rss_mb": 999,  # warmup -> drop
         "mean_cpu_pct": 0, "error_rate": 0, "recovery_s": 0, "amplification": 0,
         "lat_p50_ms": 0, "lat_p95_ms": 0, "lat_p99_ms": 0},
        {"is_synthetic": False, "rep_index": 0, "peak_rss_mb": 100,
         "mean_cpu_pct": 5, "error_rate": 0, "recovery_s": 1, "amplification": 2,
         "lat_p50_ms": 1, "lat_p95_ms": 2, "lat_p99_ms": 3},
        {"is_synthetic": False, "rep_index": 1, "peak_rss_mb": 102,
         "mean_cpu_pct": 6, "error_rate": 0, "recovery_s": 1, "amplification": 2,
         "lat_p50_ms": 1, "lat_p95_ms": 2, "lat_p99_ms": 3},
        {"is_synthetic": True, "rep_index": 0, "peak_rss_mb": 5000,  # synthetic -> drop
         "mean_cpu_pct": 0, "error_rate": 0, "recovery_s": 0, "amplification": 0,
         "lat_p50_ms": 0, "lat_p95_ms": 0, "lat_p99_ms": 0},
    ]
    s = stats.summarize_cell(rows)
    assert s["n_reps"] == 2
    assert abs(s["peak_rss_mb"]["mean"] - 101.0) < 1e-9
    assert s["lat_p95_ms"]["median"] == 2
