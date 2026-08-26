"""Concurrent benign HTTP client for the practical flood experiment.

Unlike ``http_probe.run_benign_probe`` (which runs *after* the attack
subprocess returns), this client is started *before* the flood and keeps
issuing well-formed MCP calls for the whole attack window. That is the
measurement the paper's Sec. 3 success criterion actually names: a
concurrent, well-behaved client *during* the attack.

Two channels are recorded:

  * established-session ``tools/call echo`` (an agent that already joined)
  * fresh ``initialize`` attempts (a new agent trying to join)

Primary dependent variables for the Sec. 3 criterion are the established
echo latencies and error rate. New-session outcomes are secondary and
written into ``notes``.
"""
from __future__ import annotations

import threading
import time

import httpx


class ConcurrentBenign:
    def __init__(self, base_url: str, *, echo_period_s: float = 0.25,
                 init_period_s: float = 0.5, timeout_s: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.echo_period_s = echo_period_s
        self.init_period_s = init_period_s
        self.timeout_s = timeout_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.echo_lat_ms: list[float] = []
        self.echo_ok: list[bool] = []
        self.init_lat_ms: list[float] = []
        self.init_ok: list[bool] = []
        self.session_id: str | None = None
        self.pre_init_ok = False
        self.pre_init_ms = 0.0

    def _headers(self, sid: str | None = None) -> dict:
        h = {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if sid:
            h["mcp-session-id"] = sid
        return h

    def _initialize(self, client: httpx.Client) -> tuple[bool, float, str | None]:
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "benign-concurrent", "version": "1.0"}},
        }
        t0 = time.perf_counter()
        try:
            r = client.post(f"{self.base_url}/mcp", json=body, headers=self._headers())
            dt = (time.perf_counter() - t0) * 1000
            if r.status_code != 200:
                return False, dt, None
            sid = r.headers.get("mcp-session-id")
            if sid:
                client.post(
                    f"{self.base_url}/mcp",
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers=self._headers(sid),
                )
            return True, dt, sid
        except httpx.HTTPError:
            return False, (time.perf_counter() - t0) * 1000, None

    def _echo(self, client: httpx.Client, sid: str | None) -> tuple[bool, float]:
        body = {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "benign-concurrent"}},
        }
        t0 = time.perf_counter()
        try:
            r = client.post(f"{self.base_url}/mcp", json=body,
                            headers=self._headers(sid))
            dt = (time.perf_counter() - t0) * 1000
            ok = r.status_code == 200 and '"isError":true' not in r.text
            return ok, dt
        except httpx.HTTPError:
            return False, (time.perf_counter() - t0) * 1000

    def prepare(self) -> None:
        """Open the established session before the attack starts."""
        with httpx.Client(timeout=self.timeout_s) as c:
            ok, dt, sid = self._initialize(c)
            self.pre_init_ok = ok
            self.pre_init_ms = dt
            self.session_id = sid
            if ok and sid:
                self._echo(c, sid)  # one discarded warm ping

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.timeout_s + 1.0)
            self._thread = None

    def _run(self) -> None:
        echo_client = httpx.Client(timeout=self.timeout_s)
        init_client = httpx.Client(timeout=self.timeout_s)
        next_echo = time.perf_counter()
        next_init = time.perf_counter()
        try:
            while not self._stop.is_set():
                now = time.perf_counter()
                if now >= next_echo:
                    ok, dt = self._echo(echo_client, self.session_id)
                    self.echo_lat_ms.append(dt)
                    self.echo_ok.append(ok)
                    next_echo = now + self.echo_period_s
                if now >= next_init:
                    ok, dt, _sid = self._initialize(init_client)
                    self.init_lat_ms.append(dt)
                    self.init_ok.append(ok)
                    next_init = now + self.init_period_s
                self._stop.wait(0.02)
        finally:
            echo_client.close()
            init_client.close()

    def echo_error_rate(self) -> float:
        if not self.echo_ok:
            return 1.0
        return 1.0 - (sum(self.echo_ok) / len(self.echo_ok))

    def init_error_rate(self) -> float:
        if not self.init_ok:
            return 1.0
        return 1.0 - (sum(self.init_ok) / len(self.init_ok))
