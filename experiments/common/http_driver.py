"""
Shared real-smoke-test driver body for the three vectors that reuse
servers/py_http_server.py (vectors 1, 2, 4). Each vector's run_smoke.py
only has to build the right env vars + attack command line; this module
does: start server (with a real TCP-connect readiness check), sample RSS/
CPU, run the attack under a hard timeout, run the benign probe, wait for
recovery, and ALWAYS kill the server (try/finally) so a failed run can
never leak a process that blocks the next run's port.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from common.sampler_cgroup import make_sampler
from common.schema import Record
from common.procs import start_and_wait_ready
from common.recovery import wait_for_recovery
from common.http_probe import run_benign_probe
from common.killswitch import kill_tree
from common.amplification import mem_amplification


def run_one_http_smoke(*, vector: str, sdk: str, port: int, server_cmd: list[str],
                        server_env: dict, attack_cmd: list[str],
                        load_level: int, concurrency: int, mitigation: bool,
                        attack_timeout_s: float = 30.0, notes_extra: str = "",
                        amplification_fn=None, no_attack: bool = False) -> Record:
    """`server_cmd` is the FULL command used to launch the server (e.g.
    [sys.executable, "servers/py_http_server.py"] or ["node",
    "servers/ts_http_server.mjs"]) -- port is appended automatically.

    `amplification_fn`, if given, is called as
    amplification_fn(peak_rss_mb, baseline_rss_mb, mean_cpu_pct, wall_duration_s,
    attack_result_dict) -> float, overriding the default memory-channel
    formula (used by vectors where CPU-seconds, not RSS, is the dominant
    exhausted resource -- see common/amplification.py)."""
    env = os.environ.copy()
    env.update(server_env)
    base_url = f"http://127.0.0.1:{port}"

    handle = start_and_wait_ready([*server_cmd, str(port)], env=env,
                                   timeout_s=10, check_port=port)
    if not handle.ready:
        kill_tree(handle.pid)
        raise RuntimeError(f"[{vector}] server failed to start: {handle.lines[-10:]}")

    sampler = make_sampler(handle.pid)
    try:
        sampler.start()
        time.sleep(1.0)
        baseline_rss = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0

        ts_start = time.time()
        if no_attack:
            # NO-ATTACK control arm: the attack module is deliberately NOT
            # invoked. We measure the benign client against an idle server so
            # Table 3 has an attack-absent baseline to compare against.
            attack_result = {"sent_bytes": 0, "ok": 0, "failed": 0,
                             "elapsed_s": 0.0, "no_attack": True}
        else:
            attack_out = subprocess.run(attack_cmd, capture_output=True, text=True,
                                         timeout=attack_timeout_s)
            try:
                attack_result = json.loads(attack_out.stdout.strip().splitlines()[-1])
            except Exception:
                attack_result = {"sent_bytes": 0, "ok": 0, "failed": 0, "elapsed_s": 0.0}

        latencies, error_rate = run_benign_probe(base_url, n=5, timeout_s=3.0)
        ts_end = time.time()

        recovery_s, confirmed = wait_for_recovery(handle.pid, baseline_rss)

        peak_rss = sampler.series.peak_rss_mb
        mean_cpu = sampler.series.mean_cpu_pct
    finally:
        sampler.stop()
        kill_tree(handle.pid)
        time.sleep(0.3)

    from common.schema import percentiles
    p50, p95, p99 = percentiles(latencies)
    delta_rss = max(0.0, peak_rss - baseline_rss)
    wall_duration_s = ts_end - ts_start
    if amplification_fn is not None:
        amplification = amplification_fn(peak_rss, baseline_rss, mean_cpu, wall_duration_s, attack_result)
    else:
        amplification = mem_amplification(delta_rss, attack_result.get("sent_bytes", 0))

    return Record(
        vector=vector, transport="http", sdk=sdk,
        load_level=load_level, concurrency=concurrency, mitigation=mitigation,
        peak_rss_mb=round(peak_rss, 2), mean_cpu_pct=round(mean_cpu, 2),
        lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
        error_rate=round(error_rate, 3),
        time_to_oom_s=None,
        recovery_s=round(recovery_s, 2),
        amplification=round(amplification, 3),
        ts_start=ts_start, ts_end=ts_end, is_synthetic=False,
        benign_latencies_ms=[round(x, 3) for x in latencies],
        notes=(f"REAL smoke test. baseline_rss_mb={baseline_rss:.2f}, "
               f"attack_result={attack_result}, recovery_confirmed={confirmed}. {notes_extra}"),
    )
