"""Latency recording + percentile computation for the benign client.

Standalone and dependency-free (besides stdlib `math`) so it can be unit
tested with fully synthetic data -- no MCP server, no network, no psutil.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List


@dataclass
class LatencyRecorder:
    """Accumulates per-request latency samples (in milliseconds) plus an
    error count, and computes the Table 6 latency/error fields on demand.

    Errors are tracked separately from the latency sample list: an erroring
    request contributes to `error_rate` and to `count`, but NOT to the
    percentile computation (a timed-out/failed request has no meaningful
    "latency" to rank against successful ones).
    """

    _samples_ms: List[float] = field(default_factory=list)
    _errors: int = 0
    _total: int = 0

    def record(self, latency_ms: float, error: bool = False) -> None:
        self._total += 1
        if error:
            self._errors += 1
            return
        self._samples_ms.append(latency_ms)

    @property
    def count(self) -> int:
        return self._total

    @property
    def error_count(self) -> int:
        return self._errors

    @property
    def error_rate(self) -> float:
        if self._total == 0:
            return 0.0
        return self._errors / self._total

    def percentile(self, p: float) -> float:
        """Linear-interpolation percentile (same convention as
        numpy.percentile's default), 0 <= p <= 100. Returns NaN if there are
        no successful samples to rank."""
        if not self._samples_ms:
            return math.nan
        ordered = sorted(self._samples_ms)
        if len(ordered) == 1:
            return ordered[0]
        rank = (len(ordered) - 1) * (p / 100.0)
        lo = math.floor(rank)
        hi = math.ceil(rank)
        if lo == hi:
            return ordered[int(rank)]
        return ordered[lo] + (ordered[hi] - ordered[lo]) * (rank - lo)

    def summary(self) -> dict:
        return {
            "lat_p50_ms": self.percentile(50),
            "lat_p95_ms": self.percentile(95),
            "lat_p99_ms": self.percentile(99),
            "error_rate": self.error_rate,
            "n": self._total,
        }

    def reset(self) -> None:
        self._samples_ms.clear()
        self._errors = 0
        self._total = 0
