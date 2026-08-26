"""
Hard kill-switch used by every attack script and every server driver.

Safety requirement from the task brief: "do not attempt to actually crash or
OOM your own machine badly; keep load levels modest and use a
timeout/kill-switch on every attack script." This module is imported by
every vector's smoke-test driver so the guarantee is structural, not
per-script discipline.
"""
from __future__ import annotations

import subprocess
import time

import psutil

# Hard ceiling: no single server process under test may exceed this RSS
# before the driver force-kills it, regardless of vector or mitigation
# state. Chosen well below anything that would pressure the host (this
# machine has >> 1 GB free); it only exists to bound worst-case runs.
HARD_RSS_KILL_MB = 1024

# Hard ceiling on attack-script wall time. Every smoke test finishes in a
# few seconds; this is a backstop, not the expected run length.
HARD_ATTACK_TIMEOUT_S = 20


def kill_tree(pid: int):
    try:
        parent = psutil.Process(pid)
    except psutil.Error:
        return
    children = parent.children(recursive=True)
    for c in children:
        try:
            c.kill()
        except psutil.Error:
            pass
    try:
        parent.kill()
    except psutil.Error:
        pass


class ServerGuard:
    """Wraps a running server subprocess with an RSS watchdog + hard kill.

    Use as a context manager around the attack phase:
        with ServerGuard(proc.pid) as guard:
            ... run attack, poll guard.tripped ...
    """

    def __init__(self, pid: int, rss_limit_mb: float = HARD_RSS_KILL_MB):
        self.pid = pid
        self.rss_limit_mb = rss_limit_mb
        self.tripped = False

    def check(self) -> bool:
        """Returns True (and kills the tree) if the RSS ceiling was breached."""
        try:
            p = psutil.Process(self.pid)
            rss_mb = p.memory_info().rss / (1024 * 1024)
        except psutil.Error:
            return False
        if rss_mb > self.rss_limit_mb:
            self.tripped = True
            kill_tree(self.pid)
            return True
        return False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def run_bounded(cmd: list[str], timeout_s: float = HARD_ATTACK_TIMEOUT_S, **kw):
    """Run an attack subprocess and guarantee it is dead within timeout_s."""
    proc = subprocess.Popen(cmd, **kw)
    start = time.monotonic()
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        kill_tree(proc.pid)
        proc.wait(timeout=5)
    return proc.returncode, time.monotonic() - start
