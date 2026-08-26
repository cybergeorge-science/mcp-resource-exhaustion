"""
Canonical amplification-factor implementation (P3.3 unification).

Previously the amplification formulas existed twice: as
`experiments/common/amplification.py` (the channel-specific `mem_amplification`
/`cpu_amplification` used to produce the dataset) and as
`harness/measure/results_writer.compute_amplification` (a generic ratio). This
module is now the SINGLE source of truth for all three; `experiments/common/
amplification.py` re-exports from here, and `results_writer.compute_amplification`
delegates to `ratio` here, so the code path the harness tests exercise is the
same one that produced the data.

Two cost channels are used across the 7 vectors (paper Section 4.2):

  MEMORY channel (vectors 1, 2, 3, 6):
    amplification = (peak_rss_mb - baseline_rss_mb) / attacker_bytes_sent_MB

  CPU channel (vectors 4, 5, 7):
    amplification = (mean_cpu_pct/100 * wall_duration_s) / attacker_cpu_cost_s

Both use the same epsilon-guarded division so a near-zero attacker cost yields a
large, explicitly-flagged number rather than a divide-by-zero.
"""
from __future__ import annotations

from typing import Optional

EPS = 1e-6


def ratio(target_cost: Optional[float], attacker_cost: Optional[float]) -> Optional[float]:
    """Generic amplification = target resource cost / attacker cost.

    Returns None if either cost is missing or attacker_cost is 0, so a
    missing/undefined amplification is distinguishable from a genuine
    zero-cost-attacker edge case (used by results_writer.compute_amplification)."""
    if target_cost is None or attacker_cost is None or attacker_cost == 0:
        return None
    return target_cost / attacker_cost


def mem_amplification(delta_rss_mb: float, attacker_bytes: float) -> float:
    attacker_mb = max(attacker_bytes / (1024 * 1024), EPS)
    return max(0.0, delta_rss_mb) / attacker_mb


def cpu_amplification(mean_cpu_pct: float, wall_duration_s: float, attacker_cpu_cost_s: float) -> float:
    server_cpu_s = max(0.0, mean_cpu_pct) / 100.0 * max(0.0, wall_duration_s)
    return server_cpu_s / max(attacker_cpu_cost_s, EPS)
