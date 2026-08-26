"""
Replication statistics for the real, replicated smoke-test cells (P1.1).

Self-contained (no scipy dependency -- scipy is not installed in the
reproduction environment; only numpy/pure-Python are used) so a fresh clone
can compute every reported confidence interval, median/IQR, and significance
test from the committed per-rep dataset.

What this module provides
-------------------------
* ``mean_sd_ci``      -- mean, sample SD, and a two-sided 95% t-interval
                         (Student's t for n<30; z=1.96 for n>=30). Used for
                         the roughly-symmetric dependent variables
                         (peak_rss_mb, mean_cpu_pct, error_rate, recovery_s).
* ``median_iqr``      -- median + inter-quartile range, reported for the
                         skewed benign-latency percentiles (lat_p50/p95/p99),
                         per paper Sec. 4.4 ("report IQR/median for the skewed
                         latency percentiles").
* ``mann_whitney_u``  -- two-sided Mann-Whitney U with tie-corrected normal
                         approximation + rank-biserial effect size, used for
                         every mitigation OFF-vs-ON comparison.
* ``iqr_outliers``    -- Tukey 1.5*IQR fence. Per Sec. 4.4 the primary outlier
                         rule is "discard harness-error runs, log, and re-run"
                         (handled upstream in common/reps.py, which retries a
                         failed rep rather than persisting it); this function
                         additionally FLAGS (never silently drops) statistical
                         outliers among the surviving good runs so they can be
                         reported honestly.
* ``summarize_cell``  -- roll a list of per-rep rows (dicts) for one cell up
                         into a per-DV summary.

All functions take plain lists of floats / list-of-dict rows and return plain
Python types, so they are trivially unit-testable and JSON-serializable.
"""
from __future__ import annotations

import math
from typing import Iterable, Optional

# Two-sided 95% Student-t critical values, df = 1..30. df>30 -> normal 1.96.
_T95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
    15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
    27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}


def t_critical_95(df: int) -> float:
    """Two-sided 95% t critical value for `df` degrees of freedom."""
    if df <= 0:
        return float("nan")
    if df in _T95:
        return _T95[df]
    return 1.96  # df > 30, normal approximation


def mean_sd_ci(values: Iterable[float], conf: float = 0.95) -> dict:
    """Mean, sample SD, and a two-sided CI (t-interval for n<30).

    Returns a dict with keys: n, mean, sd, sem, ci_lo, ci_hi, half_width.
    """
    if conf != 0.95:
        raise ValueError("only 95% CI supported (locked t-table)")
    xs = [float(v) for v in values]
    n = len(xs)
    if n == 0:
        return {"n": 0, "mean": None, "sd": None, "sem": None,
                "ci_lo": None, "ci_hi": None, "half_width": None}
    mean = sum(xs) / n
    if n == 1:
        return {"n": 1, "mean": mean, "sd": 0.0, "sem": 0.0,
                "ci_lo": mean, "ci_hi": mean, "half_width": 0.0}
    var = sum((x - mean) ** 2 for x in xs) / (n - 1)  # sample variance
    sd = math.sqrt(var)
    sem = sd / math.sqrt(n)
    tc = t_critical_95(n - 1)
    hw = tc * sem
    return {"n": n, "mean": mean, "sd": sd, "sem": sem,
            "ci_lo": mean - hw, "ci_hi": mean + hw, "half_width": hw}


def _quantile(sorted_xs: list[float], q: float) -> float:
    """Linear-interpolation quantile (same convention as numpy 'linear')."""
    n = len(sorted_xs)
    if n == 1:
        return sorted_xs[0]
    k = (n - 1) * q
    f = int(math.floor(k))
    c = min(f + 1, n - 1)
    if f == c:
        return sorted_xs[f]
    return sorted_xs[f] + (sorted_xs[c] - sorted_xs[f]) * (k - f)


def median_iqr(values: Iterable[float]) -> dict:
    """Median, Q1, Q3, IQR. Returns keys: n, median, q1, q3, iqr."""
    xs = sorted(float(v) for v in values)
    n = len(xs)
    if n == 0:
        return {"n": 0, "median": None, "q1": None, "q3": None, "iqr": None}
    med = _quantile(xs, 0.5)
    q1 = _quantile(xs, 0.25)
    q3 = _quantile(xs, 0.75)
    return {"n": n, "median": med, "q1": q1, "q3": q3, "iqr": q3 - q1}


def iqr_outliers(values: Iterable[float], k: float = 1.5) -> list[int]:
    """Indices of values beyond the Tukey k*IQR fence. Flags, does not drop."""
    xs = [float(v) for v in values]
    if len(xs) < 4:
        return []
    s = sorted(xs)
    q1 = _quantile(s, 0.25)
    q3 = _quantile(s, 0.75)
    iqr = q3 - q1
    lo, hi = q1 - k * iqr, q3 + k * iqr
    return [i for i, v in enumerate(xs) if v < lo or v > hi]


# --------------------------------------------------------------------------
# Mann-Whitney U (two-sided), tie-corrected normal approximation.
# --------------------------------------------------------------------------
def _rankdata(xs: list[float]) -> list[float]:
    """Average-rank of each element (1-based), ties share their mean rank."""
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    n = len(xs)
    while i < n:
        j = i
        while j + 1 < n and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0  # average of 1-based ranks i+1..j+1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def _normal_cdf(z: float) -> float:
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def mann_whitney_u(a: Iterable[float], b: Iterable[float]) -> dict:
    """Two-sided Mann-Whitney U test with tie-corrected normal approximation.

    Returns keys: n1, n2, U, U1, U2, mu_U, sigma_U, z, p_value,
    rank_biserial, method. `rank_biserial` is the effect size
    r = 1 - 2*U1/(n1*n2) in [-1, 1].
    """
    a = [float(x) for x in a]
    b = [float(x) for x in b]
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return {"n1": n1, "n2": n2, "U": None, "p_value": None,
                "rank_biserial": None, "method": "insufficient-data"}
    combined = a + b
    ranks = _rankdata(combined)
    r1 = sum(ranks[:n1])
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    U = min(u1, u2)

    mu = n1 * n2 / 2.0
    n = n1 + n2
    # tie correction
    from collections import Counter
    tie_term = sum(t ** 3 - t for t in Counter(combined).values())
    sigma_sq = (n1 * n2 / 12.0) * ((n + 1) - tie_term / (n * (n - 1)))
    sigma = math.sqrt(sigma_sq) if sigma_sq > 0 else 0.0

    if sigma == 0.0:
        z = 0.0
        p = 1.0
    else:
        # continuity correction toward the mean
        z = (U - mu + 0.5) / sigma if U < mu else (U - mu - 0.5) / sigma
        p = 2.0 * _normal_cdf(-abs(z))
        p = min(1.0, p)

    rank_biserial = 1.0 - (2.0 * u1) / (n1 * n2)
    return {"n1": n1, "n2": n2, "U": U, "U1": u1, "U2": u2,
            "mu_U": mu, "sigma_U": sigma, "z": z, "p_value": p,
            "rank_biserial": rank_biserial,
            "method": "normal-approx-tie-corrected-cc"}


# --------------------------------------------------------------------------
# Cell-level rollups.
# --------------------------------------------------------------------------
# DVs summarized with mean +/- 95% t-CI vs. median+IQR.
CI_DVS = ["peak_rss_mb", "mean_cpu_pct", "error_rate", "recovery_s", "amplification"]
IQR_DVS = ["lat_p50_ms", "lat_p95_ms", "lat_p99_ms"]


def _valid_rows(rows: list[dict]) -> list[dict]:
    """Keep only real, non-warmup rows (rep_index >= 0)."""
    out = []
    for r in rows:
        if r.get("is_synthetic"):
            continue
        ri = r.get("rep_index")
        if ri is not None and ri < 0:
            continue  # warm-up rep, discarded from stats
        out.append(r)
    return out


def summarize_cell(rows: list[dict]) -> dict:
    """Summarize one cell's list of per-rep rows into per-DV statistics.

    CI_DVS get mean +/- 95% CI; IQR_DVS get median+IQR. Also returns the raw
    per-rep value arrays and any flagged (not dropped) IQR outliers.
    """
    rows = _valid_rows(rows)
    summary: dict = {"n_reps": len(rows), "raw": {}, "outliers": {}}
    for dv in CI_DVS:
        vals = [r[dv] for r in rows if r.get(dv) is not None]
        summary[dv] = mean_sd_ci(vals)
        summary["raw"][dv] = vals
        summary["outliers"][dv] = iqr_outliers(vals)
    for dv in IQR_DVS:
        vals = [r[dv] for r in rows if r.get(dv) is not None]
        summary[dv] = median_iqr(vals)
        summary["raw"][dv] = vals
        summary["outliers"][dv] = iqr_outliers(vals)
    return summary


def fmt_ci(stat: dict, nd: int = 2) -> str:
    """'mean +/- half_width' string for a mean_sd_ci() result."""
    if stat.get("mean") is None:
        return "n/a"
    return f"{stat['mean']:.{nd}f} ± {stat['half_width']:.{nd}f}"


def fmt_median_iqr(stat: dict, nd: int = 2) -> str:
    """'median [q1, q3]' string for a median_iqr() result."""
    if stat.get("median") is None:
        return "n/a"
    return f"{stat['median']:.{nd}f} [{stat['q1']:.{nd}f}, {stat['q3']:.{nd}f}]"


# --------------------------------------------------------------------------
# Multiple-comparisons correction (added in the review pass, three-referees
# fix #5). The OFF-vs-ON significance tests form a family (one per vector x
# dependent variable), so the per-comparison p-values are adjusted with the
# Holm-Bonferroni step-down procedure, which controls the family-wise error
# rate without assuming independence. Holm is uniformly more powerful than
# plain Bonferroni and is the standard choice for a small, heterogeneous
# family of tests like this one.
# --------------------------------------------------------------------------
def holm_bonferroni(pvalues: list[float], alpha: float = 0.05) -> list[dict]:
    """Holm-Bonferroni step-down correction.

    Takes a list of raw two-sided p-values (order preserved in the output)
    and returns, per input p, a dict with the original p, the Holm-adjusted
    p (monotone, capped at 1.0), and a boolean `reject` at family-wise
    ``alpha``. ``None`` p-values pass through untouched (reject=False).
    """
    indexed = [(i, p) for i, p in enumerate(pvalues) if p is not None]
    m = len(indexed)
    out = [{"p_value": p, "p_holm": None, "reject": False} for p in pvalues]
    if m == 0:
        return out
    # ascending by raw p
    indexed.sort(key=lambda ip: ip[1])
    running_max = 0.0
    for rank, (orig_i, p) in enumerate(indexed):
        adj = (m - rank) * p           # step-down multiplier
        adj = min(1.0, max(adj, running_max))  # enforce monotonicity + cap
        running_max = adj
        out[orig_i]["p_holm"] = adj
        out[orig_i]["reject"] = adj <= alpha
    return out
