"""Helper to launch a reference-server subprocess, block until it prints a
READY marker line AND (for network servers) actually accepts a TCP
connection, or time out. Always be killable via killswitch.

Relying on the printed marker alone is not sufficient: the server scripts
print READY just before handing control to their event loop, so a bind
failure (e.g. a stale server from a previous run still holding the port)
happens AFTER the marker is printed. Every driver MUST also wrap its
attack phase in try/finally so a failed/timed-out attack subprocess can
never leak a server process that then blocks the next run's port.
"""
from __future__ import annotations

import socket
import subprocess
import threading
import time


class ServerHandle:
    def __init__(self, proc: subprocess.Popen, pid: int, ready: bool, lines: list[str]):
        self.proc = proc
        self.pid = pid
        self.ready = ready
        self.lines = lines


def _port_open(host: str, port: int, timeout_s: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def start_and_wait_ready(cmd: list[str], env: dict, ready_prefix: str = "READY",
                          timeout_s: float = 10.0, cwd: str | None = None,
                          check_port: int | None = None,
                          check_host: str = "127.0.0.1") -> ServerHandle:
    proc = subprocess.Popen(
        cmd, env=env, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    lines: list[str] = []
    ready_evt = threading.Event()

    def reader():
        try:
            for line in proc.stdout:
                lines.append(line.rstrip())
                if line.startswith(ready_prefix):
                    ready_evt.set()
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    marker_seen = ready_evt.wait(timeout_s)

    ready = marker_seen
    if marker_seen and check_port is not None:
        deadline = time.monotonic() + timeout_s
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                # process already exited (e.g. bind failure) -- never ready
                ready = False
                break
            if _port_open(check_host, check_port):
                ready = True
                break
            time.sleep(0.1)

    return ServerHandle(proc, proc.pid, ready, lines)
