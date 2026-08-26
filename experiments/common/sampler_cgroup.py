"""
cgroup v2 resource sampler (P1.3) -- CODE-READY, EXECUTION PENDING A LINUX HOST.

The paper's primary measurements use common/sampler.py (psutil, Windows) which
is an OS-process-level approximation of the cgroup accounting a containerized
Linux MCP deployment actually faces. This module is the Linux/cgroup-v2
counterpart: it reads the target's `memory.peak` and `cpu.stat` from the cgroup
v2 filesystem, giving kernel-accounted peak memory and CPU-time rather than
interval-sampled psutil snapshots (removing the sub-interval aliasing threat
named in paper Sec. 7.3).

It presents the SAME interface as common/sampler.ProcessSampler
(``start()`` / ``stop()`` / ``series.peak_rss_mb`` / ``series.mean_cpu_pct``) so
a Linux re-run can swap samplers via ``make_sampler(pid)`` with no driver
changes.

IMPORTANT: this file has NOT been executed. The measurement host for the paper
is Windows, which has no cgroups (``/sys/fs/cgroup`` absent), so ``make_sampler``
falls back to the psutil ProcessSampler here. On a Linux cgroup-v2 host, run the
containers built by experiments/servers/Dockerfile.* (which apply cpu.max /
memory.max caps) and this sampler activates automatically. No cgroup number
appears anywhere in the paper's dataset; when this is run on Linux, its output
must be labeled as a separate Linux/cgroup test bed.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field

CGROUP_ROOT = "/sys/fs/cgroup"
SAMPLE_INTERVAL_S = 0.2


def cgroup_v2_available() -> bool:
    """True iff a cgroup v2 hierarchy is mounted (Linux only)."""
    return os.path.isfile(os.path.join(CGROUP_ROOT, "cgroup.controllers"))


def _proc_cgroup_path(pid: int) -> str | None:
    """Resolve the cgroup v2 directory for `pid` from /proc/<pid>/cgroup.

    The v2 line looks like ``0::/some/group``; the absolute path is
    CGROUP_ROOT + that suffix.
    """
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as fh:
            for line in fh:
                parts = line.strip().split(":", 2)
                if len(parts) == 3 and parts[0] == "0":
                    return os.path.join(CGROUP_ROOT, parts[2].lstrip("/"))
    except OSError:
        return None
    return None


def _read_int(path: str) -> int | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _read_cpu_usage_usec(cg_dir: str) -> int | None:
    """usage_usec from cpu.stat (total CPU time consumed by the cgroup)."""
    try:
        with open(os.path.join(cg_dir, "cpu.stat"), encoding="utf-8") as fh:
            for line in fh:
                k, _, v = line.strip().partition(" ")
                if k == "usage_usec":
                    return int(v)
    except (OSError, ValueError):
        return None
    return None


@dataclass
class CgroupSampleSeries:
    rss_mb: list = field(default_factory=list)
    cpu_pct: list = field(default_factory=list)
    t: list = field(default_factory=list)
    _peak_bytes: int = 0

    @property
    def peak_rss_mb(self) -> float:
        # prefer the kernel's own high-water mark (memory.peak) if captured
        if self._peak_bytes:
            return self._peak_bytes / (1024 * 1024)
        return max(self.rss_mb) if self.rss_mb else 0.0

    @property
    def mean_cpu_pct(self) -> float:
        return (sum(self.cpu_pct) / len(self.cpu_pct)) if self.cpu_pct else 0.0


class CgroupSampler:
    """cgroup v2 analogue of ProcessSampler.

    peak memory := memory.peak (kernel high-water mark, no aliasing).
    CPU% per interval := d(usage_usec)/d(wall_usec) * 100 (can exceed 100 on
    multi-core, matching the psutil convention the paper already documents).
    """

    def __init__(self, pid: int, interval_s: float = SAMPLE_INTERVAL_S):
        self.pid = pid
        self.interval_s = interval_s
        self.series = CgroupSampleSeries()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._cg = _proc_cgroup_path(pid)
        if self._cg is None:
            raise RuntimeError(f"no cgroup v2 path for pid {pid}")

    def _run(self):
        t0 = time.monotonic()
        last_usage = _read_cpu_usage_usec(self._cg)
        last_wall = time.monotonic()
        while not self._stop.is_set():
            cur_mem = _read_int(os.path.join(self._cg, "memory.current"))
            if cur_mem is not None:
                self.series.rss_mb.append(cur_mem / (1024 * 1024))
            usage = _read_cpu_usage_usec(self._cg)
            now = time.monotonic()
            if usage is not None and last_usage is not None:
                d_cpu_usec = usage - last_usage
                d_wall_usec = (now - last_wall) * 1e6
                if d_wall_usec > 0:
                    self.series.cpu_pct.append(100.0 * d_cpu_usec / d_wall_usec)
            last_usage, last_wall = usage, now
            self.series.t.append(now - t0)
            time.sleep(self.interval_s)
        # capture kernel high-water mark at stop
        peak = _read_int(os.path.join(self._cg, "memory.peak"))
        if peak is not None:
            self.series._peak_bytes = peak

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


def make_sampler(pid: int, interval_s: float = SAMPLE_INTERVAL_S):
    """Return a CgroupSampler on a cgroup-v2 host, else the psutil
    ProcessSampler. Lets a Linux re-run activate cgroup accounting with no
    driver changes; on Windows this always returns the psutil sampler."""
    if cgroup_v2_available():
        try:
            return CgroupSampler(pid, interval_s)
        except RuntimeError:
            pass
    from common.sampler import ProcessSampler
    return ProcessSampler(pid, interval_s)
