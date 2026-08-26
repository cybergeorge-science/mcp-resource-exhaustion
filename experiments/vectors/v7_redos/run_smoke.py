"""
Real smoke-test driver for Vector 7 -- ReDoS in input validation
(CWE-1333), stdio transport, Python reference server.
"""
import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from common.sampler_cgroup import make_sampler
from common.schema import Record, percentiles, write_records
from common.stdio_launch import start_stdio_server
from common.stdio_client import StdioClient, run_benign_stdio_probe
from common.recovery import wait_for_recovery
from common.killswitch import kill_tree
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX
from common.amplification import cpu_amplification

sys.path.insert(0, os.path.dirname(__file__))
from attack import send_pathological

VECTOR = "v7_redos"
TRANSPORT = "stdio"
SDK = "python"
LOAD_IDX = int(os.environ.get("SMOKE_LOAD_INDEX", ANCHOR_LOAD_INDEX[VECTOR]))
LENGTH = LOAD_LEVELS[VECTOR]["values"][LOAD_IDX - 1]  # 26 chars at anchor
CONCURRENCY = 1  # stdio is inherently single-connection; see REPORT.md

PY = sys.executable
SERVER_SCRIPT = os.path.join(ROOT, "servers", "py_stdio_server.py")

MIT_MAX_LEN = 20  # below the 26-char attack payload


def one_run(mitigation: bool, no_attack: bool = False):
    env = os.environ.copy()
    env["MIT_MAX_INPUT_LEN"] = str(MIT_MAX_LEN) if mitigation else "0"

    handle = start_stdio_server([PY, SERVER_SCRIPT], env=env, timeout_s=10)
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
            # NO-ATTACK control arm: the pathological ReDoS input is not sent.
            attack_result = {"build_s": 1e-6, "no_attack": True}
        else:
            attack_result = send_pathological(client, LENGTH, timeout_s=15.0)

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
    wall_duration_s = ts_end - ts_start
    attacker_cpu_cost_s = attack_result.get("build_s", 1e-6)
    amplification = cpu_amplification(mean_cpu, wall_duration_s, attacker_cpu_cost_s)

    rec = Record(
        vector=VECTOR, transport=TRANSPORT, sdk=SDK,
        load_level=LOAD_IDX, concurrency=CONCURRENCY,
        mitigation=mitigation,
        peak_rss_mb=round(peak_rss, 2), mean_cpu_pct=round(mean_cpu, 2),
        lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
        error_rate=round(error_rate, 3),
        time_to_oom_s=None,  # CPU-bound vector; OOM is not the failure mode -- see REPORT.md
        recovery_s=round(recovery_s, 2),
        amplification=round(amplification, 3),
        ts_start=ts_start, ts_end=ts_end, is_synthetic=False,
        benign_latencies_ms=[round(x, 3) for x in latencies],
        notes=(f"REAL smoke test. baseline_rss_mb={baseline_rss:.2f}, length={LENGTH}, "
               f"pattern='^(a+)+$', attack_result={attack_result}, "
               f"recovery_confirmed={confirmed}, "
               f"mitigation_max_input_len={MIT_MAX_LEN if mitigation else 'n/a'}"),
    )
    return rec


if __name__ == "__main__":
    from common.reps import run_smoke_main
    run_smoke_main(VECTOR, one_run)
