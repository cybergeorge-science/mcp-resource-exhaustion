"""
Tiny benign MCP client used to measure the thing a DoS paper actually cares
about: how much does an attack degrade service for a LEGITIMATE, well-formed
client. Not a full SDK client -- just enough raw HTTP/JSON-RPC framing to
perform `initialize` once and then repeat `tools/call echo` N times,
recording per-call latency and success/failure.
"""
from __future__ import annotations

import time
import httpx


class BenignHttpClient:
    def __init__(self, base_url: str, timeout_s: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.session_id = None
        self._client = httpx.Client(timeout=timeout_s)

    def _headers(self):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.session_id:
            h["mcp-session-id"] = self.session_id
        return h

    def initialize(self) -> tuple[bool, float]:
        """Returns (ok, latency_ms) -- latency is always the REAL measured
        round-trip time of the initialize attempt, even on failure/rejection
        (e.g. a 429 from a rate limiter). Never a fabricated timeout value."""
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "benign-probe", "version": "1.0"},
            },
        }
        t0 = time.perf_counter()
        try:
            r = self._client.post(f"{self.base_url}/mcp", json=body, headers=self._headers())
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code != 200:
                return False, dt
            self.session_id = r.headers.get("mcp-session-id")
            self._client.post(
                f"{self.base_url}/mcp",
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=self._headers(),
            )
            return True, dt
        except httpx.HTTPError:
            dt = (time.perf_counter() - t0) * 1000
            return False, dt

    def call_echo_once(self) -> tuple[bool, float]:
        """Returns (ok, latency_ms)."""
        body = {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "benign-probe"}},
        }
        t0 = time.perf_counter()
        try:
            r = self._client.post(f"{self.base_url}/mcp", json=body, headers=self._headers())
            dt = (time.perf_counter() - t0) * 1000
            ok = r.status_code == 200 and '"isError":true' not in r.text
            return ok, dt
        except httpx.HTTPError:
            dt = (time.perf_counter() - t0) * 1000
            return False, dt

    def close(self):
        self._client.close()


def run_benign_probe(base_url: str, n: int, timeout_s: float = 3.0):
    """Runs `initialize` then up to n echo calls, ALL with real measured
    latency (no fabricated timeout placeholders). If initialize itself
    fails/is rejected (e.g. by a rate limiter), the probe still attempts
    the n echo calls without a session -- these will get a fast real
    rejection/error response from the server rather than hanging, so the
    reported latencies stay genuine. Returns (latencies_ms, error_rate)
    computed over all n+1 real attempts."""
    client = BenignHttpClient(base_url, timeout_s=timeout_s)
    latencies = []
    errors = 0
    init_ok, init_dt = client.initialize()
    latencies.append(init_dt)
    if not init_ok:
        errors += 1
    for _ in range(n):
        ok, dt = client.call_echo_once()
        latencies.append(dt)
        if not ok:
            errors += 1
    client.close()
    total = len(latencies)
    return latencies, (errors / total if total else 0.0)
