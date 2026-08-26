"""
Python-side equivalent of attack.mjs's sendUnboundedLine(), used by
run_smoke.py so the same process that owns the sampled server's stdin
pipe can also drive the attack (needed because psutil, not Node, is doing
the cross-process RSS sampling here -- see common/sampler.py). attack.mjs
remains the standalone, SDK-adjacent demonstration of this exact
mechanism for anyone running it directly against their own server.
"""
from __future__ import annotations

import time


def send_unbounded_line(proc, size_mb: float, chunk_kb: int = 256) -> dict:
    """Writes a single never-terminated JSON-RPC 'line' of size_mb
    megabytes to proc.stdin in chunk_kb-sized pieces, stopping early (and
    recording it) if the pipe errors out -- exactly what happens once a
    mitigated server hits maxBufferSize and closes the connection."""
    chunk = "A" * (chunk_kb * 1024)
    total_bytes = int(size_mb * 1024 * 1024)
    sent = 0
    aborted = False
    t0 = time.perf_counter()
    while sent < total_bytes:
        remaining = total_bytes - sent
        piece = chunk if remaining >= len(chunk) else chunk[:remaining]
        try:
            proc.stdin.write(piece)
            proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            aborted = True
            break
        sent += len(piece)
    elapsed_s = time.perf_counter() - t0
    return {"sent_bytes": sent, "aborted": aborted, "elapsed_s": elapsed_s,
            "ok": 1 if not aborted else 0, "failed": 1 if aborted else 0}
