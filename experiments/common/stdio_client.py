"""
Minimal newline-delimited JSON-RPC client for talking directly to a stdio
MCP server's stdin/stdout pipes -- used by both the stdio attack scripts
and the stdio benign-probe. Deliberately NOT the SDK's own client: an
attacker (and our benign-latency probe) only needs the wire framing, not
the full client library.

A background thread continuously drains the child's stdout into a queue,
because Windows anonymous pipes cannot be polled with select()/selectors,
so a timeout-bounded read needs a thread + Queue.get(timeout=...).
"""
from __future__ import annotations

import json
import queue
import subprocess
import threading
import time


class StdioClient:
    def __init__(self, proc: subprocess.Popen):
        self.proc = proc
        self._q: queue.Queue[str] = queue.Queue()
        self._t = threading.Thread(target=self._reader, daemon=True)
        self._t.start()

    def _reader(self):
        try:
            for line in self.proc.stdout:
                self._q.put(line)
        except Exception:
            pass

    def send(self, obj: dict):
        line = json.dumps(obj)
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def send_raw(self, raw: str):
        """Send a raw (possibly non-JSON, possibly unterminated) string
        directly, for vectors that need to violate normal framing."""
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()

    def recv(self, timeout_s: float = 5.0):
        try:
            line = self._q.get(timeout=timeout_s)
        except queue.Empty:
            return None
        try:
            return json.loads(line)
        except Exception:
            return None

    def initialize(self, timeout_s: float = 5.0) -> tuple[bool, float]:
        t0 = time.perf_counter()
        self.send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "stdio-probe", "version": "1.0"}},
        })
        resp = self.recv(timeout_s)
        dt = (time.perf_counter() - t0) * 1000
        if resp is None or "result" not in resp:
            return False, dt
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return True, dt

    def call_tool(self, name: str, args: dict, req_id: int = 2, timeout_s: float = 5.0):
        t0 = time.perf_counter()
        self.send({
            "jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": name, "arguments": args},
        })
        resp = self.recv(timeout_s)
        dt = (time.perf_counter() - t0) * 1000
        ok = resp is not None and "error" not in resp and resp.get("result", {}).get("isError") is not True
        return ok, dt, resp


def run_benign_stdio_probe(client: "StdioClient", n: int, timeout_s: float = 3.0,
                            already_initialized: bool = True):
    """Same contract as common/http_probe.run_benign_probe but over stdio.

    IMPORTANT: takes an existing StdioClient (one reader thread per pipe).
    Do NOT construct a second StdioClient around the same subprocess's
    stdout -- two reader threads racing `for line in proc.stdout`
    non-deterministically split responses between two queues, which
    silently starves whichever client's recv() is waiting (this was
    caught empirically: it manifested as every benign-probe call timing
    out at exactly `timeout_s` even though the server had already replied).
    """
    latencies = []
    errors = 0
    if not already_initialized:
        ok, dt = client.initialize(timeout_s)
        latencies.append(dt)
        if not ok:
            errors += 1
    for i in range(n):
        ok, dt, _ = client.call_tool("echo", {"text": "benign-probe"}, req_id=100 + i, timeout_s=timeout_s)
        latencies.append(dt)
        if not ok:
            errors += 1
    total = len(latencies)
    return latencies, (errors / total if total else 0.0)
