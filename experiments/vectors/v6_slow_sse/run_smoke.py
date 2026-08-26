"""
Real smoke-test driver for Vector 6 -- Slow-SSE / slow read (CWE-400),
SSE transport, TypeScript reference server.
"""
import json
import os
import shutil
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from common.sampler_cgroup import make_sampler
from common.schema import Record, percentiles, write_records
from common.procs import start_and_wait_ready
from common.recovery import wait_for_recovery
from common.killswitch import kill_tree
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX
from common.amplification import mem_amplification
from attack_helper import open_slow_reader, benign_sse_probe

VECTOR = "v6_slow_sse"
TRANSPORT = "sse"
SDK = "typescript"
PORT = 8817
LOAD_IDX = int(os.environ.get("SMOKE_LOAD_INDEX", ANCHOR_LOAD_INDEX[VECTOR]))
PUSH_MB = LOAD_LEVELS[VECTOR]["values"][LOAD_IDX - 1]  # 10 MB at anchor
CONCURRENCY = 1  # one slow connection; see REPORT.md for the concurrency-axis note

NODE = shutil.which("node") or "node"
SERVER_SCRIPT = os.path.join(ROOT, "servers", "ts_sse_server.mjs")

MIT_MAX_BUFFERED_BYTES = 512 * 1024  # 512 KB cap, well below the 10 MB push


def one_run(mitigation: bool, no_attack: bool = False):
    env = os.environ.copy()
    env["PUSH_MB"] = str(PUSH_MB)
    env["MIT_SSE_MAX_BUFFERED_BYTES"] = str(MIT_MAX_BUFFERED_BYTES) if mitigation else "0"

    handle = start_and_wait_ready([NODE, SERVER_SCRIPT, str(PORT)], env=env,
                                   timeout_s=10, check_port=PORT)
    if not handle.ready:
        kill_tree(handle.pid)
        raise RuntimeError(f"[{VECTOR}] server failed to start: {handle.lines[-10:]}")

    sampler = make_sampler(handle.pid)
    try:
        sampler.start()
        time.sleep(1.0)
        baseline_rss = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0

        ts_start = time.time()
        sock = None
        if no_attack:
            # NO-ATTACK control arm: no slow reader is opened. Give the server
            # the same brief settle time, then probe the idle server.
            time.sleep(2.5)
        else:
            sock, _ = open_slow_reader("127.0.0.1", PORT)
            # give the server's push loop time to either finish the burst or
            # hit the mitigation cutoff
            time.sleep(2.5)

        latencies, error_rate = benign_sse_probe("127.0.0.1", PORT, n=3, timeout_s=3.0)
        ts_end = time.time()

        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

        recovery_s, confirmed = wait_for_recovery(handle.pid, baseline_rss)

        peak_rss = sampler.series.peak_rss_mb
        mean_cpu = sampler.series.mean_cpu_pct
    finally:
        sampler.stop()
        kill_tree(handle.pid)
        time.sleep(0.3)

    p50, p95, p99 = percentiles(latencies)
    delta_rss = max(0.0, peak_rss - baseline_rss)
    # attacker cost proxy: the slow reader only ever sends ~100 bytes (the
    # GET request line + headers) -- everything after that is free for it
    attacker_bytes = 200
    amplification = mem_amplification(delta_rss, attacker_bytes)

    rec = Record(
        vector=VECTOR, transport=TRANSPORT, sdk=SDK,
        load_level=LOAD_IDX, concurrency=CONCURRENCY,
        mitigation=mitigation,
        peak_rss_mb=round(peak_rss, 2), mean_cpu_pct=round(mean_cpu, 2),
        lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
        error_rate=round(error_rate, 3),
        time_to_oom_s=None,
        recovery_s=round(recovery_s, 2),
        amplification=round(amplification, 3),
        ts_start=ts_start, ts_end=ts_end, is_synthetic=False,
        benign_latencies_ms=[round(x, 3) for x in latencies],
        notes=(f"REAL smoke test. baseline_rss_mb={baseline_rss:.2f}, push_mb={PUSH_MB}, "
               f"recovery_confirmed={confirmed}, "
               f"mitigation_max_buffered_bytes={MIT_MAX_BUFFERED_BYTES if mitigation else 'n/a'}, "
               f"benign_probe=fresh-connection time-to-first-byte"),
    )
    return rec


if __name__ == "__main__":
    from common.reps import run_smoke_main
    run_smoke_main(VECTOR, one_run)
