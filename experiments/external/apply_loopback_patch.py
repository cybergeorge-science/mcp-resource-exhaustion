"""
Reproducible loopback-bind patch for the external target.

@modelcontextprotocol/server-everything's HTTP and SSE transports call
`app.listen(PORT, ...)` with no host argument, so Node binds ALL interfaces
(`::`/0.0.0.0) and exposes a LAN-reachable listener. This experiment is
loopback-only by design, so we bind the stock server to 127.0.0.1. Only the
listen host changes; the server's request-handling / parsing code -- the code
under test -- is untouched.

Run this after any `npm install` in external/ to re-apply the bind:
    python apply_loopback_patch.py
Idempotent: re-running when already patched is a no-op.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "node_modules", "@modelcontextprotocol",
                    "server-everything", "dist", "transports")
EDITS = [
    ("streamableHttp.js", "const server = app.listen(PORT, () => {",
     'const server = app.listen(PORT, "127.0.0.1", () => {'),
    ("sse.js", "app.listen(PORT, () => {",
     'app.listen(PORT, "127.0.0.1", () => {'),
]


def main():
    for fname, old, new in EDITS:
        path = os.path.join(BASE, fname)
        if not os.path.exists(path):
            print(f"SKIP {fname}: not found (install server-everything first)")
            continue
        src = open(path, encoding="utf-8").read()
        if new in src:
            print(f"OK   {fname}: already bound to 127.0.0.1")
        elif old in src:
            open(path, "w", encoding="utf-8").write(src.replace(old, new))
            print(f"PATCHED {fname}: now binds 127.0.0.1")
        else:
            print(f"WARN {fname}: expected listen() call not found (version drift?)")


if __name__ == "__main__":
    main()
