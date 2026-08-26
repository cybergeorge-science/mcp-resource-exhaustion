"""Benign client: issues well-formed requests at a steady cadence and
records per-request latency via LatencyRecorder.

Transport/SDK-agnostic by design: `request_fn` performs ONE request/response
round trip against the real target (a stdio/streamable-HTTP/SSE MCP call)
and either returns normally or raises. This module never constructs an MCP
request itself -- wiring `request_fn` to a real `mcp` (Python SDK) or
`@modelcontextprotocol/sdk` (TypeScript SDK, via a small companion process)
client call is the integrator's job. The smoke tests in tests/ pass a
synthetic `request_fn` with no MCP server involved at all.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .latency import LatencyRecorder


@dataclass
class BenignClientConfig:
    rate_hz: float = 10.0
    duration_s: float = 30.0
    request_timeout_s: float = 5.0


class BenignClient:
    """Fixed-rate synthetic-load client used to observe target degradation
    under attack.

    Usage::

        client = BenignClient(my_mcp_request_fn, BenignClientConfig(rate_hz=10, duration_s=30))
        client.start_background()          # non-blocking, runs on a daemon thread
        ...                                  # drive attack traffic concurrently
        client.stop()
        summary = client.recorder.summary()  # lat_p50/p95/p99_ms, error_rate
    """

    def __init__(
        self,
        request_fn: Callable[[], None],
        config: Optional[BenignClientConfig] = None,
    ):
        self.request_fn = request_fn
        self.config = config or BenignClientConfig()
        self.recorder = LatencyRecorder()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _run_one(self) -> None:
        start = time.perf_counter()
        error = False
        try:
            self.request_fn()
        except Exception:
            error = True
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if elapsed_ms > self.config.request_timeout_s * 1000.0:
            error = True
        self.recorder.record(elapsed_ms, error=error)

    def run_for(self, duration_s: Optional[float] = None) -> LatencyRecorder:
        """Blocking: issue requests at `rate_hz` for `duration_s` seconds,
        return the recorder. Safe to call directly in tests (no threads)."""
        duration_s = duration_s if duration_s is not None else self.config.duration_s
        period = 1.0 / self.config.rate_hz if self.config.rate_hz > 0 else 0.0
        deadline = time.perf_counter() + duration_s
        next_tick = time.perf_counter()
        while time.perf_counter() < deadline and not self._stop_event.is_set():
            self._run_one()
            next_tick += period
            sleep_s = next_tick - time.perf_counter()
            if sleep_s > 0:
                time.sleep(sleep_s)
        return self.recorder

    def start_background(self, duration_s: Optional[float] = None) -> threading.Thread:
        """Non-blocking variant so the harness can run the resource sampler
        and benign client concurrently with a vector module's load
        generation. Returns the daemon thread (already started)."""
        self._stop_event.clear()
        thread = threading.Thread(target=self.run_for, args=(duration_s,), daemon=True)
        self._thread = thread
        thread.start()
        return thread

    def stop(self, join_timeout_s: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout_s)
