"""Smoke tests for measure.sampler.ResourceSampler.

Per the task's constraints, this samples a synthetic local process (the
current pytest process itself, or a trivial subprocess it spawns) rather
than a real MCP server -- that integration is a different agent's job.
"""
import os
import subprocess
import sys
import time

from measure.sampler import ResourceSampler, ResourceSamplerConfig


def test_sampler_collects_samples_at_roughly_the_configured_interval():
    sampler = ResourceSampler(os.getpid(), ResourceSamplerConfig(interval_s=0.05))
    sampler.start()

    # do some synthetic CPU/memory work so there's something to observe
    junk = [bytearray(1024 * 1024) for _ in range(5)]
    time.sleep(0.3)
    del junk

    sampler.stop()
    samples = sampler.samples

    assert len(samples) > 0
    # ~0.3s / 0.05s interval ~= 6 samples; allow generous slack
    assert 2 <= len(samples) <= 15
    for s in samples:
        assert s.rss_bytes > 0
        assert s.cpu_pct >= 0.0


def test_summary_reports_peak_rss_and_mean_cpu():
    sampler = ResourceSampler(os.getpid(), ResourceSamplerConfig(interval_s=0.05))
    sampler.start()
    time.sleep(0.2)
    sampler.stop()

    summary = sampler.summary()
    assert summary["n_samples"] > 0
    assert summary["peak_rss_mb"] is not None and summary["peak_rss_mb"] > 0
    assert summary["mean_cpu_pct"] is not None and summary["mean_cpu_pct"] >= 0.0


def test_summary_on_never_started_sampler_is_all_none():
    sampler = ResourceSampler(os.getpid(), ResourceSamplerConfig(interval_s=0.05))
    summary = sampler.summary()
    assert summary == {"peak_rss_mb": None, "mean_cpu_pct": None, "n_samples": 0}


def test_sampler_against_a_real_subprocess_target():
    """Exercises the intended real-world usage shape (sampling a PID that is
    NOT the test process itself) using a trivial synthetic subprocess --
    still not a real MCP server, per the task's scope boundary."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(1.5)"],
    )
    try:
        sampler = ResourceSampler(proc.pid, ResourceSamplerConfig(interval_s=0.05))
        sampler.start()
        time.sleep(0.5)
        sampler.stop()
        summary = sampler.summary()
        assert summary["n_samples"] > 0
        assert summary["peak_rss_mb"] > 0
    finally:
        proc.terminate()
        proc.wait(timeout=5)
