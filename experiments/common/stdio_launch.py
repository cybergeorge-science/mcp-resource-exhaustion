"""
Launches a stdio MCP server subprocess with stdin/stdout reserved
EXCLUSIVELY for JSON-RPC framing, and stderr used for the READY marker +
diagnostics (mirrors servers/py_stdio_server.py and the TypeScript stdio
server, both of which print READY to stderr for exactly this reason).
"""
from __future__ import annotations

import subprocess
import threading
import time


class StdioServerHandle:
    def __init__(self, proc: subprocess.Popen, ready: bool, stderr_lines: list[str]):
        self.proc = proc
        self.pid = proc.pid
        self.ready = ready
        self.stderr_lines = stderr_lines


def start_stdio_server(cmd: list[str], env: dict, ready_prefix: str = "READY",
                        timeout_s: float = 10.0, cwd: str | None = None) -> StdioServerHandle:
    proc = subprocess.Popen(
        cmd, env=env, cwd=cwd,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    lines: list[str] = []
    ready_evt = threading.Event()

    def reader():
        try:
            for line in proc.stderr:
                lines.append(line.rstrip())
                if line.startswith(ready_prefix):
                    ready_evt.set()
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    ready = ready_evt.wait(timeout_s)
    time.sleep(0.2)
    return StdioServerHandle(proc, ready, lines)
