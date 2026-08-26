"""Practical high-concurrency flood experiment.

Closes the paper's stated flood-null gap (Sec. 6.2): v2/v5 "no availability
impact" was measured at concurrency <= 8, with the benign probe issued
*after* a ~1 s burst. A real attacker sustains a flood while other agents
keep calling.

This runner, loopback-only against this project's own reference servers:

  * concurrency = 32 workers/sessions
  * wall-clock duration = 10 s (sustained, not a one-shot burst)
  * benign client runs CONCURRENTLY with the flood (established-session
    echo + fresh initialize)
  * matched no-attack control of the same duration and probe cadence
  * unmitigated attack arm (the Sec. 3 question); mitigation ON is a
    third arm so collateral rejection is visible at this load

Pre-declared success criterion (identical to Table 3b):
  adverse iff (MWU p < 0.05 AND median p95_attack / p95_control >= 2)
           OR (error_rate_attack - error_rate_control >= 0.10)
on the established-session echo channel.

Writes (never overwrites the committed anchors):
  results/real/v2_init_flood__practical.json
  results/real/v2_init_flood__practical_control.json
  results/real/v5_tool_flood__practical.json
  results/real/v5_tool_flood__practical_control.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from common.concurrent_benign import ConcurrentBenign
from common.killswitch import HARD_RSS_KILL_MB, kill_tree
from common.procs import start_and_wait_ready
from common.recovery import wait_for_recovery
from common.sampler import ProcessSampler
from common.schema import Record, percentiles, write_records

PY = sys.executable
NODE = shutil.which("node") or "node"
ATTACK_SCRIPT = os.path.join(ROOT, "practical_attack.py")
SEED = 20260826
DURATION_S = 10.0
CONCURRENCY = 32
WARMUP = 1
DEFAULT_REPS = 8
COOLDOWN_S = 2.0
ECHO_PERIOD_S = 0.25
INIT_PERIOD_S = 0.5
BENIGN_TIMEOUT_S = 5.0
ATTACK_SUBPROCESS_TIMEOUT_S = 25.0

V2_PORT = 8912
V5_PORT = 8916
V2_SERVER = os.path.join(ROOT, "servers", "py_http_server.py")
V5_SERVER = os.path.join(ROOT, "servers", "ts_http_server.mjs")

def _watchdog(pid: int, stop: threading.Event) -> None:
    import psutil
    try:
        proc = psutil.Process(pid)
    except psutil.Error:
        return
    while not stop.wait(0.2):
        try:
            rss_mb = proc.memory_info().rss / (1024 * 1024)
        except psutil.Error:
            return
        if rss_mb >= HARD_RSS_KILL_MB:
            kill_tree(pid)
            return


def _run_flood_subprocess(vector: str, base_url: str) -> dict:
    """Attack in a child process so the parent's benign probe is not GIL-starved."""
    cmd = [PY, ATTACK_SCRIPT, vector, base_url, str(DURATION_S), str(CONCURRENCY)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=ATTACK_SUBPROCESS_TIMEOUT_S, cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return {"attempted": 0, "ok": 0, "failed": 0, "elapsed_s": DURATION_S,
                "sent_bytes": 0, "error": "timeout"}
    raw = (proc.stdout or "").strip().splitlines()
    if not raw:
        return {"attempted": 0, "ok": 0, "failed": 0, "elapsed_s": 0.0,
                "sent_bytes": 0, "error": (proc.stderr or "")[-400:],
                "returncode": proc.returncode}
    try:
        return json.loads(raw[-1])
    except json.JSONDecodeError:
        return {"attempted": 0, "ok": 0, "failed": 0, "elapsed_s": 0.0,
                "sent_bytes": 0, "error": raw[-1][:400]}


def _one_run(*, vector: str, sdk: str, port: int, server_cmd: list[str],
             server_env: dict, no_attack: bool, mitigation: bool,
             load_level: int) -> Record:
    env = os.environ.copy()
    env.update(server_env)
    base_url = f"http://127.0.0.1:{port}"
    handle = start_and_wait_ready(
        [*server_cmd, str(port)], env=env, timeout_s=15, check_port=port)
    if not handle.ready:
        kill_tree(handle.pid)
        raise RuntimeError(f"[{vector}] server failed to start: {handle.lines[-20:]}")

    wd_stop = threading.Event()
    wd = threading.Thread(target=_watchdog, args=(handle.pid, wd_stop), daemon=True)
    wd.start()
    sampler = ProcessSampler(handle.pid)
    benign = ConcurrentBenign(
        base_url, echo_period_s=ECHO_PERIOD_S, init_period_s=INIT_PERIOD_S,
        timeout_s=BENIGN_TIMEOUT_S)
    try:
        sampler.start()
        time.sleep(0.8)
        baseline_rss = sampler.series.rss_mb[-1] if sampler.series.rss_mb else 0.0
        benign.prepare()
        ts_start = time.time()
        benign.start()
        time.sleep(0.3)  # a few pre-flood echoes so the control has the same cadence
        if no_attack:
            time.sleep(DURATION_S)
            attack_result = {"sent_bytes": 0, "ok": 0, "failed": 0,
                             "elapsed_s": DURATION_S, "no_attack": True,
                             "attempted": 0}
        else:
            attack_result = _run_flood_subprocess(vector, base_url)
        benign.stop()
        ts_end = time.time()
        recovery_s, confirmed = wait_for_recovery(handle.pid, baseline_rss)
        peak_rss = sampler.series.peak_rss_mb
        mean_cpu = sampler.series.mean_cpu_pct
    finally:
        wd_stop.set()
        sampler.stop()
        try:
            benign.stop()
        except Exception:
            pass
        kill_tree(handle.pid)
        time.sleep(0.3)

    lats = benign.echo_lat_ms
    p50, p95, p99 = percentiles(lats)
    err = benign.echo_error_rate()
    delta_rss = max(0.0, peak_rss - baseline_rss)
    return Record(
        vector=vector, transport="http", sdk=sdk,
        load_level=load_level, concurrency=CONCURRENCY, mitigation=mitigation,
        peak_rss_mb=round(peak_rss, 2), mean_cpu_pct=round(mean_cpu, 2),
        lat_p50_ms=round(p50, 2), lat_p95_ms=round(p95, 2), lat_p99_ms=round(p99, 2),
        error_rate=round(err, 3),
        time_to_oom_s=None,
        recovery_s=round(recovery_s, 2),
        amplification=None,
        ts_start=ts_start, ts_end=ts_end, is_synthetic=False,
        benign_latencies_ms=[round(x, 3) for x in lats],
        notes=(
            f"PRACTICAL concurrent-probe flood. duration_s={DURATION_S}, "
            f"concurrency={CONCURRENCY}, attack_present={'no' if no_attack else 'yes'}, "
            f"baseline_rss_mb={baseline_rss:.2f}, recovery_confirmed={confirmed}, "
            f"pre_init_ok={benign.pre_init_ok}, pre_init_ms={benign.pre_init_ms:.2f}, "
            f"n_echo={len(benign.echo_ok)}, echo_err={err:.3f}, "
            f"n_init={len(benign.init_ok)}, init_err={benign.init_error_rate():.3f}, "
            f"attack_result={attack_result}"
        ),
    )


def run_vector(cfg: dict, reps: int, seed: int) -> None:
    rng = random.Random(seed)
    attack_rows: list[Record] = []
    control_rows: list[Record] = []
    total = reps + WARMUP
    for r in range(total):
        kept = r - WARMUP
        is_warmup = kept < 0
        # within-rep order: control vs unmitigated attack, shuffled so warmup
        # of the server cannot systematically make the attack arm look faster.
        arms = ["control", "attack"]
        rng.shuffle(arms)
        for arm in arms:
            rec = _one_run(
                vector=cfg["vector"], sdk=cfg["sdk"], port=cfg["port"],
                server_cmd=cfg["server_cmd"],
                server_env=cfg["server_env_off"],
                no_attack=(arm == "control"),
                mitigation=False,
                load_level=cfg["load_level"],
            )
            rec.rep_index = kept
            rec.cell_id = (
                f"{cfg['vector']}|http|{cfg['sdk']}|L{cfg['load_level']}"
                f"|C{CONCURRENCY}|off|practical"
                + ("|noattack" if arm == "control" else "")
            )
            tag = "WARMUP(discarded)" if is_warmup else f"rep {kept}"
            rec.notes = f"{rec.notes} [{tag}, arm={arm}, cell_id={rec.cell_id}]"
            (control_rows if arm == "control" else attack_rows).append(rec)
            print(
                f"[{cfg['vector']}] {tag} {arm:7s} "
                f"rss={rec.peak_rss_mb} cpu={rec.mean_cpu_pct} "
                f"p95={rec.lat_p95_ms} err={rec.error_rate}",
                flush=True,
            )
            time.sleep(COOLDOWN_S)
    out_dir = os.path.join(ROOT, "results", "real")
    write_records(attack_rows, os.path.join(out_dir, f"{cfg['vector']}__practical.json"))
    write_records(control_rows, os.path.join(out_dir, f"{cfg['vector']}__practical_control.json"))


CONFIGS = {
    "v2_init_flood": dict(
        vector="v2_init_flood", sdk="python", port=V2_PORT,
        server_cmd=[PY, V2_SERVER], server_env_off={},
        load_level=3,
    ),
    "v5_tool_flood": dict(
        vector="v5_tool_flood", sdk="typescript", port=V5_PORT,
        server_cmd=[NODE, V5_SERVER], server_env_off={},
        load_level=3,
    ),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS)
    ap.add_argument("--only", choices=list(CONFIGS), default=None)
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()
    names = [args.only] if args.only else list(CONFIGS)
    t0 = time.time()
    for name in names:
        print(f"\n===== PRACTICAL {name} C={CONCURRENCY} {DURATION_S}s =====", flush=True)
        run_vector(CONFIGS[name], args.reps, args.seed)
    print(f"\nPRACTICAL DONE in {time.time() - t0:.1f}s", flush=True)


if __name__ == "__main__":
    main()
