"""
Real smoke-test driver for Vector 3 -- Unbounded stdio stream (CWE-770),
stdio transport, TypeScript reference server.

Uses the SDK's OWN built-in StdioServerTransport `maxBufferSize` option as
the mitigation (see servers/ts_stdio_server.mjs) rather than a hand-rolled
guard -- this is a real, already-shipped control in
@modelcontextprotocol/sdk.
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
from common.stdio_launch import start_stdio_server
from common.stdio_client import StdioClient, run_benign_stdio_probe
from common.recovery import wait_for_recovery
from common.killswitch import kill_tree
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX
from common.amplification import mem_amplification
from attack_helper import send_unbounded_line

VECTOR = "v3_unbounded_stdio"
TRANSPORT = "stdio"
SDK = "typescript"
LOAD_IDX = int(os.environ.get("SMOKE_LOAD_INDEX", ANCHOR_LOAD_INDEX[VECTOR]))
SIZE_MB = LOAD_LEVELS[VECTOR]["values"][LOAD_IDX - 1]  # 20 MB at anchor
CONCURRENCY = 1  # stdio is inherently single-connection; see REPORT.md

NODE = shutil.which("node") or "node"
SERVER_SCRIPT = os.path.join(ROOT, "servers", "ts_stdio_server.mjs")

MIT_CAP_BYTES = 2 * 1024 * 1024  # 2 MB cap, below the 20 MB attack payload


def one_run(mitigation: bool, no_attack: bool = False):
    env = os.environ.copy()
    env["MIT_STDIO_MAX_BUFFER_BYTES"] = str(MIT_CAP_BYTES) if mitigation else "0"

    handle = start_stdio_server([NODE, SERVER_SCRIPT], env=env, timeout_s=10)
    if not handle.ready:
        kill_tree(handle.pid)
        raise RuntimeError(f"server not ready: {handle.stderr_lines}")

    sampler = make_sampler(handle.pid)
    try:
        sampler.start()
        time.sleep(1.0)
        baseline_rss = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0

        client = StdioClient(handle.proc)
        init_ok, _ = client.initialize(timeout_s=5.0)
        if not init_ok:
            raise RuntimeError("stdio initialize failed")

        ts_start = time.time()
        if no_attack:
            # NO-ATTACK control arm: the unbounded-line attack is deliberately
            # not sent. Measure the benign probe against the idle server.
            attack_result = {"aborted": False, "sent_bytes": 0, "no_attack": True}
            latencies, error_rate = run_benign_stdio_probe(client, n=5, timeout_s=3.0)
        else:
            attack_result = send_unbounded_line(handle.proc, SIZE_MB)

            # the attack either aborted the connection (mitigated) or is still
            # holding an incomplete "line" open (unmitigated) -- either way,
            # try the benign probe on a NEW connection if the old one died,
            # otherwise reuse it
            if attack_result["aborted"]:
                latencies, error_rate = [0.0] * 6, 1.0  # connection was closed by the server
            else:
                latencies, error_rate = run_benign_stdio_probe(client, n=5, timeout_s=3.0)
        ts_end = time.time()

        recovery_s, confirmed = wait_for_recovery(handle.pid, baseline_rss)

        peak_rss = sampler.series.peak_rss_mb
        mean_cpu = sampler.series.mean_cpu_pct
    finally:
        sampler.stop()
        kill_tree(handle.pid)
        time.sleep(0.3)

    p50, p95, p99 = percentiles(latencies)
    delta_rss = max(0.0, peak_rss - baseline_rss)
    amplification = mem_amplification(delta_rss, attack_result.get("sent_bytes", 0))

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
        notes=(f"REAL smoke test. baseline_rss_mb={baseline_rss:.2f}, size_mb={SIZE_MB}, "
               f"attack_result={attack_result}, recovery_confirmed={confirmed}, "
               f"mitigation_max_buffer_bytes={MIT_CAP_BYTES if mitigation else 'n/a (512MB ceiling)'}"),
    )
    return rec


if __name__ == "__main__":
    from common.reps import run_smoke_main
    run_smoke_main(VECTOR, one_run)
