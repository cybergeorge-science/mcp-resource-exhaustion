"""
Cross-validate common/stats.py against SciPy reference output.

The reproduction environment ships no SciPy on purpose (see the stats.py
docstring): a fresh clone must be able to recompute every reported CI,
median/IQR, and significance test with only numpy/pure-Python. This test is
therefore a *validation-only* check that runs when SciPy is available (CI /
developer machine) and is skipped otherwise. It answers the three-referees
review's fix #5 ("self-implemented statistics never cross-checked against
scipy/R") by pinning our Mann-Whitney U p-values, the tie-corrected normal
approximation, and the rank-biserial effect size to SciPy's own results.
"""
import math
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common import stats  # noqa: E402

scipy_stats = pytest.importorskip(
    "scipy.stats",
    reason="SciPy is intentionally absent from the repro env; validation-only.")


# A spread of shapes: fully separated, overlapping, tied, and skewed.
CASES = [
    ([291.1, 292.0, 290.5, 293.2, 291.8, 289.9, 292.4, 290.1, 291.6, 292.9],
     [70.6, 70.4, 70.8, 70.5, 70.7, 70.3, 70.9, 70.6, 70.5, 70.7]),          # separated
    ([5.1, 6.2, 4.8, 5.9, 6.0, 5.5, 4.9, 6.1, 5.3, 5.7],
     [5.4, 5.0, 6.3, 4.7, 5.8, 6.2, 5.1, 5.6, 4.9, 6.0]),                    # overlapping
    ([1.0, 1.0, 2.0, 2.0, 3.0, 3.0],
     [2.0, 2.0, 3.0, 3.0, 4.0, 4.0]),                                        # ties
    ([0.0, 0.0, 0.0, 0.0, 1.3, 0.0, 0.0, 0.0, 0.0, 1.3],
     [62.1, 63.0, 61.5, 64.2, 62.8, 60.9, 63.4, 61.1, 62.6, 63.9]),         # skewed
]


@pytest.mark.parametrize("a,b", CASES)
def test_mann_whitney_matches_scipy(a, b):
    ours = stats.mann_whitney_u(a, b)
    ref = scipy_stats.mannwhitneyu(a, b, alternative="two-sided",
                                   method="asymptotic", use_continuity=True)
    # SciPy reports U for the first sample; we report min(U1, U2).
    assert math.isclose(ours["U"], min(ref.statistic, len(a) * len(b) - ref.statistic),
                        rel_tol=0, abs_tol=1e-9)
    # p-values agree to 3 decimals (both use the tie-corrected normal approx).
    assert math.isclose(ours["p_value"], ref.pvalue, rel_tol=0.02, abs_tol=1e-3)


@pytest.mark.parametrize("a,b", CASES)
def test_rank_biserial_matches_scipy(a, b):
    ours = stats.mann_whitney_u(a, b)
    ref = scipy_stats.mannwhitneyu(a, b, alternative="two-sided")
    # rank-biserial r = 1 - 2*U1/(n1*n2), with U1 SciPy's first-sample U.
    n1, n2 = len(a), len(b)
    r_ref = 1.0 - 2.0 * ref.statistic / (n1 * n2)
    assert math.isclose(ours["rank_biserial"], r_ref, rel_tol=0, abs_tol=1e-9)


def test_holm_matches_statsmodels_if_available():
    sm = pytest.importorskip("statsmodels.stats.multitest",
                             reason="statsmodels optional")
    pvals = [0.0002, 0.0002, 0.0008, 0.371, 0.636, 0.0001, 0.0122]
    ours = [h["p_holm"] for h in stats.holm_bonferroni(pvals)]
    reject, adj, _, _ = sm.multipletests(pvals, alpha=0.05, method="holm")
    for a, b in zip(ours, adj):
        assert math.isclose(a, b, rel_tol=0, abs_tol=1e-9)
