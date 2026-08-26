"""Regression tests for the pure, deterministic formulas in
experiments/common/ that actually produced every real number reported in
Section 6 of the paper (amplification channels, percentile computation).

Added by the review pass: before this file, the harness's 37 pytest tests
(harness/tests/) covered only the harness/measure/ scaffold, which the
experiments team ultimately did NOT use to produce the real dataset --
they built their own parallel common/ implementation (paper Section 5.3)
that had zero automated test coverage of its own. This file starts closing
that gap for the two formulas most load-bearing for Section 6's headline
claims: the amplification channels (Section 4.2, Table 9, Figure 4) and the
percentile reconstruction used by every latency column in Tables 7-10 and
Figure 3. It intentionally does not attempt to test the I/O-heavy pieces
(sampler.py, recovery.py, procs.py, killswitch.py, the stdio/http drivers)
since those need a live subprocess and are exercised, in practice, by every
real smoke-test run itself -- see experiments/REPORT.md Section 5 for the
concurrency/race/port-collision bugs that real usage caught.
"""
import math

import pytest

from common.amplification import cpu_amplification, mem_amplification
from common.schema import percentiles


def test_mem_amplification_basic_ratio():
    # 10 MB of RSS growth for 5 MB sent -> amplification factor 2.0
    assert mem_amplification(10.0, 5 * 1024 * 1024) == 2.0


def test_mem_amplification_zero_growth_is_zero_not_negative():
    # A mitigation that fully prevents growth (e.g. v3-ON in the real data)
    # must report exactly 0.0, not a small negative number from rounding.
    assert mem_amplification(0.0, 2 * 1024 * 1024) == 0.0


def test_mem_amplification_clamps_negative_growth_to_zero():
    # peak_rss dipping below baseline (measurement noise) must not produce
    # a negative amplification.
    assert mem_amplification(-5.0, 1024 * 1024) == 0.0


def test_mem_amplification_epsilon_guards_zero_attacker_bytes():
    # A zero-byte attacker cost must not raise ZeroDivisionError; the
    # module's EPS guard should yield a large but finite number instead.
    result = mem_amplification(10.0, 0)
    assert math.isfinite(result)
    assert result > 0


def test_cpu_amplification_basic_ratio():
    # 50% mean CPU sustained for 2 wall-seconds = 1.0 server CPU-second;
    # attacker spent 0.1 CPU-seconds constructing the request -> 10x.
    assert cpu_amplification(50.0, 2.0, 0.1) == pytest.approx(10.0)


def test_cpu_amplification_zero_attacker_cost_is_finite():
    result = cpu_amplification(59.11, 2.02, 0.0)
    assert math.isfinite(result)
    assert result > 0


def test_percentiles_single_value_returns_that_value_for_all_three():
    p50, p95, p99 = percentiles([4.38])
    assert p50 == p95 == p99 == 4.38


def test_percentiles_empty_list_returns_zeros_not_an_error():
    assert percentiles([]) == (0.0, 0.0, 0.0)


def test_percentiles_are_monotonic_nondecreasing():
    values = [1.0, 2.0, 3.0, 10.0, 50.0, 51.0, 52.0, 53.0, 100.0]
    p50, p95, p99 = percentiles(values)
    assert p50 <= p95 <= p99
    assert min(values) <= p50
    assert p99 <= max(values)
