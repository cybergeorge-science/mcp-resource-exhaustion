"""
Cross-SDK resource sampler used by every vector's smoke-test driver.

Windows has no cgroups, so this is an OS-process-level APPROXIMATION using
psutil: peak RSS (working set) and mean CPU% of the *target server process*,
sampled on a fixed wall-clock interval from a background thread. This works
identically whether the sampled PID belongs to the Python reference server
or the Node/TypeScript reference server, so the same sampler is reused for
both SDKs.

This is explicitly NOT a cgroup memory.peak / cpu.stat reading (Phase 3 of
implementation-plan.txt assumes Linux cgroups); it is the best available
approximation on Windows and is labeled as such everywhere it is reported.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import psutil

SAMPLE_INTERVAL_S = 0.2  # fixed across all runs, per Phase 3 requirement


@dataclass
class SampleSeries:
    rss_mb: list = field(default_factory=list)
    cpu_pct: list = field(default_factory=list)
    t: list = field(default_factory=list)

    @property
    def peak_rss_mb(self) -> float:
        return max(self.rss_mb) if self.rss_mb else 0.0

    @property
    def mean_cpu_pct(self) -> float:
        return (sum(self.cpu_pct) / len(self.cpu_pct)) if self.cpu_pct else 0.0


class ProcessSampler:
    """Samples RSS + CPU% of a given OS pid at SAMPLE_INTERVAL_S until stopped."""

    def __init__(self, pid: int, interval_s: float = SAMPLE_INTERVAL_S):
        self.pid = pid
        self.interval_s = interval_s
        self.series = SampleSeries()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc = psutil.Process(pid)
        # prime cpu_percent (first call always returns 0.0)
        try:
            self._proc.cpu_percent(interval=None)
        except psutil.Error:
            pass

    def _run(self):
        t0 = time.monotonic()
        while not self._stop.is_set():
            try:
                with self._proc.oneshot():
                    rss = self._proc.memory_info().rss / (1024 * 1024)
                    cpu = self._proc.cpu_percent(interval=None)
                self.series.rss_mb.append(rss)
                self.series.cpu_pct.append(cpu)
                self.series.t.append(time.monotonic() - t0)
            except psutil.Error:
                break
            time.sleep(self.interval_s)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
