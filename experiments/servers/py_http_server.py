"""
Shared Python-SDK reference server (Streamable HTTP transport) used by
vectors 1 (oversized body), 2 (init/session flood) and 4 (deep nested JSON).

This is the REAL official `mcp` package (pip "mcp", modelcontextprotocol/
python-sdk), built with FastMCP, exposing one trivial tool ("echo") so a
benign client has something legitimate to call. It is wrapped in a small
amount of hand-written ASGI middleware that implements the three
mitigations below -- these do NOT exist in the stock SDK, they are the
"corresponding control" this project is contributing, toggled independently
by environment variables so each vector can be smoke-tested with its own
mitigation isolated (the other two stay off).

Env vars (all default OFF = "0"):
  MIT_BODY_CAP_BYTES   int, >0 enables the request body size cap (vector 1)
  MIT_SESSION_RATE     int, >0 enables session-creation rate limiting,
                        meaning: max N "initialize" requests accepted per
                        MIT_SESSION_WINDOW_S seconds (vector 2)
  MIT_SESSION_WINDOW_S float, window for the above (default 1.0)
  MIT_JSON_MAX_DEPTH   int, >0 enables a cheap pre-parse brace/bracket
                        depth scan that rejects overly-nested JSON bodies
                        before the real JSON parser ever sees them (vector 4)

Binds to 127.0.0.1 ONLY. Port taken from argv[1] (default 8765).
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

from mcp.server.fastmcp import FastMCP

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
HOST = "127.0.0.1"

MIT_BODY_CAP_BYTES = int(os.environ.get("MIT_BODY_CAP_BYTES", "0"))
MIT_SESSION_RATE = int(os.environ.get("MIT_SESSION_RATE", "0"))
MIT_SESSION_WINDOW_S = float(os.environ.get("MIT_SESSION_WINDOW_S", "1.0"))
MIT_JSON_MAX_DEPTH = int(os.environ.get("MIT_JSON_MAX_DEPTH", "0"))

mcp = FastMCP("dos-research-reference-server", host=HOST, port=PORT,
              stateless_http=False, json_response=True)


@mcp.tool()
def echo(text: str) -> str:
    """Trivial benign tool used to measure legitimate-client latency."""
    return text


# ---------------------------------------------------------------------------
# Mitigation 1 (vector 1): request body size cap
# ---------------------------------------------------------------------------
class BodyCapMiddleware:
    """Pure-ASGI middleware. Streams the request body and aborts with a 413
    the moment cumulative bytes exceed MIT_BODY_CAP_BYTES, WITHOUT ever
    buffering the oversized payload into a Python object and without
    letting it reach the JSON-RPC parser. If under the cap, transparently
    replays the buffered body to the wrapped app."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if self.max_bytes <= 0 or scope["type"] != "http":
            return await self.app(scope, receive, send)

        chunks = []
        total = 0
        over = False
        more_body = True
        while more_body:
            msg = await receive()
            if msg["type"] != "http.request":
                break
            body = msg.get("body", b"") or b""
            more_body = msg.get("more_body", False)
            if not over:
                total += len(body)
                if total > self.max_bytes:
                    over = True
                    chunks = None  # drop anything buffered so far
                else:
                    chunks.append(body)

        if over:
            await send({
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error":"payload too large","mitigation":"body_size_cap"}',
            })
            return

        buffered = [{"type": "http.request", "body": b"".join(chunks), "more_body": False}]

        async def replay_receive():
            if buffered:
                return buffered.pop()
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


# ---------------------------------------------------------------------------
# Mitigation 2 (vector 2): session-creation rate limit
# ---------------------------------------------------------------------------
class SessionRateLimitMiddleware:
    """Token-bucket-ish limiter keyed globally (loopback lab -- in a real
    deployment this would be keyed per client IP / auth principal). Any
    POST to the MCP endpoint that does NOT carry an existing
    `mcp-session-id` header is treated as a session-creation attempt
    (typically an `initialize` call). If more than `rate` such requests
    land inside `window_s` seconds, further ones are rejected with 429
    before ever reaching the SDK's session manager."""

    def __init__(self, app, rate: int, window_s: float):
        self.app = app
        self.rate = rate
        self.window_s = window_s
        self._timestamps: list[float] = []

    async def __call__(self, scope, receive, send):
        if self.rate <= 0 or scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers") or [])
        has_session = b"mcp-session-id" in headers
        if scope["method"] == "POST" and not has_session:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < self.window_s]
            if len(self._timestamps) >= self.rate:
                await send({
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [(b"content-type", b"application/json")],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"error":"too many new sessions","mitigation":"session_rate_limit"}',
                })
                return
            self._timestamps.append(now)

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Mitigation 3 (vector 4): JSON nesting-depth limit (pre-parse scan)
# ---------------------------------------------------------------------------
def max_bracket_depth(data: bytes, cap: int) -> int:
    """Cheap O(n) scan for max {}/[] nesting depth, bails out early past
    `cap` so a pathologically deep payload can't burn CPU here either."""
    depth = 0
    peak = 0
    in_string = False
    escape = False
    for b in data:
        c = chr(b)
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "{[":
            depth += 1
            peak = max(peak, depth)
            if peak > cap:
                return peak
        elif c in "}]":
            depth = max(0, depth - 1)
    return peak


class JsonDepthLimitMiddleware:
    def __init__(self, app, max_depth: int):
        self.app = app
        self.max_depth = max_depth

    async def __call__(self, scope, receive, send):
        if self.max_depth <= 0 or scope["type"] != "http":
            return await self.app(scope, receive, send)

        chunks = []
        more_body = True
        while more_body:
            msg = await receive()
            if msg["type"] != "http.request":
                break
            chunks.append(msg.get("body", b"") or b"")
            more_body = msg.get("more_body", False)
        body = b"".join(chunks)

        depth = max_bracket_depth(body, self.max_depth)
        if depth > self.max_depth:
            await send({
                "type": "http.response.start",
                "status": 400,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"error":"json nesting too deep","mitigation":"json_depth_limit"}',
            })
            return

        buffered = [{"type": "http.request", "body": body, "more_body": False}]

        async def replay_receive():
            if buffered:
                return buffered.pop()
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


def build_app():
    app = mcp.streamable_http_app()
    if MIT_JSON_MAX_DEPTH > 0:
        app = JsonDepthLimitMiddleware(app, MIT_JSON_MAX_DEPTH)
    if MIT_SESSION_RATE > 0:
        app = SessionRateLimitMiddleware(app, MIT_SESSION_RATE, MIT_SESSION_WINDOW_S)
    if MIT_BODY_CAP_BYTES > 0:
        app = BodyCapMiddleware(app, MIT_BODY_CAP_BYTES)
    return app


if __name__ == "__main__":
    import uvicorn
    print(f"READY pid={os.getpid()} host={HOST} port={PORT}", flush=True)
    uvicorn.run(build_app(), host=HOST, port=PORT, log_level="warning")
