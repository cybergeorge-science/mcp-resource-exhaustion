"""
P2.1 deliberate real-OOM demonstration for Vector 1 (oversized body).

Unlike run_smoke.py (10 replicated reps under a generous 1024 MB container
cap, meant never to OOM so the replicated dataset isn't corrupted), this is a
single, separate, deliberately-tight-capped run: the exact same anchor attack
(size_mb/concurrency from common/grid.py) replayed against a container whose
`--memory` is set below the anchor's own observed unmitigated peak, so the
kernel's cgroup-v2 OOM killer has to act. It targets the SERVER subprocess
specifically (the memory hog in the cgroup), not the driver, so the driver
survives to time the kill and read the final memory.peak.

Not part of the replicated statistics -- a one-off, clearly-labeled real
(is_synthetic:false) measurement of an actual time_to_oom_s, which every row
in the main dataset lacks (paper Sec 6.2: "time_to_oom was never reached").

Usage (inside the cgroup-capped container):
  python vectors/v1_oversized_body/oom_demo.py
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from common.procs import start_and_wait_ready
from common.sampler_cgroup import make_sampler, cgroup_v2_available
from common.killswitch import kill_tree
from common.grid import LOAD_LEVELS, ANCHOR_LOAD_INDEX, ANCHOR_CONCURRENCY

PORT = 8811
SIZE_MB = float(sys.argv[1]) if len(sys.argv) > 1 else \
    LOAD_LEVELS["v1_oversized_body"]["values"][ANCHOR_LOAD_INDEX["v1_oversized_body"] - 1]
CONCURRENCY = int(sys.argv[2]) if len(sys.argv) > 2 else ANCHOR_CONCURRENCY
PY = sys.executable
SERVER_SCRIPT = os.path.join(ROOT, "servers", "py_http_server.py")
ATTACK_SCRIPT = os.path.join(os.path.dirname(__file__), "attack.py")
POLL_S = 0.05
MAX_WAIT_S = 40.0


def main():
    env = os.environ.copy()
    env["MIT_BODY_CAP_BYTES"] = "0"  # mitigation OFF -- the exhaustion case

    handle = start_and_wait_ready([PY, SERVER_SCRIPT, str(PORT)], env=env,
                                   timeout_s=10, check_port=PORT)
    if not handle.ready:
        print(json.dumps({"error": "server failed to start", "lines": handle.lines[-10:]}))
        return

    sampler = make_sampler(handle.pid)
    sampler_kind = type(sampler).__name__
    sampler.start()

    t0 = time.time()
    attack_proc = subprocess.Popen(
        [PY, ATTACK_SCRIPT, f"http://127.0.0.1:{PORT}", str(SIZE_MB), str(CONCURRENCY), "30"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )

    server_died_at = None
    attack_done_at = None
    deadline = t0 + MAX_WAIT_S
    while time.time() < deadline:
        if handle.proc.poll() is not None and server_died_at is None:
            server_died_at = time.time()
            break
        if attack_proc.poll() is not None and attack_done_at is None:
            attack_done_at = time.time()
        time.sleep(POLL_S)

    sampler.stop()
    server_exit_code = handle.proc.poll()
    time_to_oom_s = round(server_died_at - t0, 3) if server_died_at is not None else None

    try:
        attack_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        attack_proc.kill()

    result = {
        "vector": "v1_oversized_body",
        "mitigation": False,
        "is_synthetic": False,
        "design": "deliberate single-shot real-OOM demonstration, NOT part of the replicated dataset",
        "sampler_kind": sampler_kind,
        "cgroup_v2_available": cgroup_v2_available(),
        "size_mb": SIZE_MB,
        "concurrency": CONCURRENCY,
        "server_pid": handle.pid,
        "server_exit_code": server_exit_code,
        "server_oom_killed": server_exit_code == -9,
        "time_to_oom_s": time_to_oom_s,
        "peak_rss_mb": round(sampler.series.peak_rss_mb, 2),
        "mean_cpu_pct": round(sampler.series.mean_cpu_pct, 2),
        "ts_start": t0,
        "ts_server_died": server_died_at,
    }
    print(json.dumps(result, indent=2))

    kill_tree(handle.pid)
    try:
        kill_tree(attack_proc.pid)
    except Exception:
        pass


if __name__ == "__main__":
    main()
