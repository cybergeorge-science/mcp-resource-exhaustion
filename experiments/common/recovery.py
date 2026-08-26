"""
Recovery-time measurement, used identically by every vector's real
smoke-test driver.

Definition (locked, per Phase 3 requirement to fix this before running
anything): a server has "recovered" once its RSS has fallen to within
RECOVERY_RATIO (110%) of its pre-attack baseline RSS for RECOVERY_CONSEC
consecutive samples (at the fixed 0.2s sampler interval, i.e. >= 0.4s
sustained). If the process has not recovered within MAX_WAIT_S, recovery_s
is reported as MAX_WAIT_S with an explicit "did not confirm recovery"
note -- never silently extrapolated.
"""
from __future__ import annotations

import time

import psutil

RECOVERY_RATIO = 1.10
RECOVERY_CONSEC = 2
MAX_WAIT_S = 8.0
POLL_S = 0.2


def wait_for_recovery(pid: int, baseline_rss_mb: float,
                       max_wait_s: float = MAX_WAIT_S) -> tuple[float, bool]:
    """Returns (recovery_s, confirmed)."""
    try:
        proc = psutil.Process(pid)
    except psutil.Error:
        return 0.0, False
    threshold = baseline_rss_mb * RECOVERY_RATIO
    t0 = time.monotonic()
    consec = 0
    while time.monotonic() - t0 < max_wait_s:
        try:
            rss_mb = proc.memory_info().rss / (1024 * 1024)
        except psutil.Error:
            return time.monotonic() - t0, False
        if rss_mb <= threshold:
            consec += 1
            if consec >= RECOVERY_CONSEC:
                return time.monotonic() - t0, True
        else:
            consec = 0
        time.sleep(POLL_S)
    return max_wait_s, False
