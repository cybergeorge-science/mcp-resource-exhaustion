"""Resource sampler: samples a target process's RSS and CPU% at a fixed
interval using psutil.

KNOWN LIMITATION -- documented, not silently substituted:

This measurement harness was built and tested on Windows, which has no
cgroup interface. psutil.Process-based sampling is a reasonable
development-time proxy but is NOT equivalent to Linux cgroup
memory.peak / cpu.stat, for concrete reasons:

  - psutil's memory_info().rss is point-sampled at whatever cadence this
    class polls at; it can miss a true peak that occurs between two polls.
    Linux cgroup memory.peak is a kernel-maintained running maximum and
    cannot miss a spike regardless of sampling cadence.
  - psutil's cpu_percent() is normalized over wall-clock time since the
    previous call and can disagree with cgroup cpu.stat's usage_usec under
    scheduler contention or when other processes share the host.
  - There is no OOM-kill notification on Windows equivalent to a cgroup OOM
    event. `time_to_oom_s` computed from this sampler alone can only be a
    heuristic (e.g. process exit with an abnormal/non-zero code, or RSS
    crossing a configured ceiling) -- never a true kernel OOM signal.

On a genuine Linux experiment run, use the cgroup v2 backend implemented in
`experiments/common/sampler_cgroup.py` (P1.3): it reads
`/sys/fs/cgroup/<slice>/memory.peak` and `.../cpu.stat` (usage_usec) and
exposes the same `start()/stop()/series` interface, and
`sampler_cgroup.make_sampler(pid)` auto-selects it when `/sys/fs/cgroup` is a
v2 hierarchy (falling back to the psutil path here otherwise). That module is
CODE-READY but has NOT been executed for this paper's dataset, because the
measurement host is Windows (no cgroups); when run on Linux its output must be
recorded as a separate Linux/cgroup test bed in paper Table 5, and psutil-
derived and cgroup-derived numbers must never be reported as interchangeable.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import List, Optional

import psutil

DEFAULT_INTERVAL_S = 0.1  # 100ms, pinned per implementation-plan.txt Phase 3 ("must be constant across all runs")


@dataclass
class ResourceSample:
    ts: float  # time.time() epoch seconds
    rss_bytes: int
    cpu_pct: float


@dataclass
class ResourceSamplerConfig:
    interval_s: float = DEFAULT_INTERVAL_S


class ResourceSampler:
    """Background sampler for one target PID.

    Usage::

        sampler = ResourceSampler(target_pid, ResourceSamplerConfig(interval_s=0.1))
        sampler.start()
        ...                        # run attack / benign client concurrently
        sampler.stop()
        summary = sampler.summary()   # {"peak_rss_mb": ..., "mean_cpu_pct": ..., "n_samples": ...}
    """

    def __init__(self, pid: int, config: Optional[ResourceSamplerConfig] = None):
        self.pid = pid
        self.config = config or ResourceSamplerConfig()
        self._proc = psutil.Process(pid)
        self._samples: List[ResourceSample] = []
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Prime cpu_percent()'s internal delta counter. psutil's documented
        # pattern: the first call always returns 0.0 (or a meaningless
        # value) and establishes the baseline for subsequent calls.
        self._proc.cpu_percent(interval=None)

    def _poll_once(self) -> Optional[ResourceSample]:
        try:
            with self._proc.oneshot():
                rss = self._proc.memory_info().rss
                cpu = self._proc.cpu_percent(interval=None)
            return ResourceSample(ts=time.time(), rss_bytes=rss, cpu_pct=cpu)
        except psutil.NoSuchProcess:
            return None

    def _run(self) -> None:
        while not self._stop_event.is_set():
            sample = self._poll_once()
            if sample is None:
                break
            self._samples.append(sample)
            self._stop_event.wait(self.config.interval_s)

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, join_timeout_s: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout_s)

    @property
    def samples(self) -> List[ResourceSample]:
        return list(self._samples)

    def summary(self) -> dict:
        if not self._samples:
            return {"peak_rss_mb": None, "mean_cpu_pct": None, "n_samples": 0}
        peak_rss_mb = max(s.rss_bytes for s in self._samples) / (1024 * 1024)
        mean_cpu_pct = sum(s.cpu_pct for s in self._samples) / len(self._samples)
        return {
            "peak_rss_mb": peak_rss_mb,
            "mean_cpu_pct": mean_cpu_pct,
            "n_samples": len(self._samples),
        }
