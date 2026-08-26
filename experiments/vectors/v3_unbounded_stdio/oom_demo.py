"""
P2.1 deliberate real-OOM demonstration for Vector 3 (unbounded stdio stream).

Same design rationale as vectors/v1_oversized_body/oom_demo.py: a single,
separate, deliberately-tight-capped run (not part of the replicated 10-rep
dataset) meant to force the kernel's cgroup-v2 OOM killer to act, so this
paper can report at least one real, measured time_to_oom_s instead of the
`null` in every row of the main dataset.

Node/V8 is the more promising target for an actual kernel OOM-kill than v1's
Python http server: v1's request body ends up in Python bytes objects backed
by malloc(), and Linux's malloc path can return NULL/ENOMEM to userspace,
which Python turns into a catchable MemoryError -- the process survives
(confirmed empirically: three attempts at 100-2000 MB against 150-280 MB caps
all plateaued at the cap without dying). Node's stdio server here
concatenates the incoming stream into one ever-growing string/Buffer; V8's
heap growth touches newly-committed pages for the first time as it grows,
and a first-touch page fault cannot be answered with an error code the way a
malloc() call can -- if the kernel can't reclaim enough to satisfy it, the
cgroup-v2 OOM killer has to pick a process to kill.

Usage (inside the cgroup-capped container):
  python vectors/v3_unbounded_stdio/oom_demo.py [size_mb]
"""
import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from common.sampler_cgroup import make_sampler, cgroup_v2_available
from common.stdio_launch import start_stdio_server
from common.killswitch import kill_tree
from attack_helper import send_unbounded_line

SIZE_MB = float(sys.argv[1]) if len(sys.argv) > 1 else 500.0
NODE = "node"
SERVER_SCRIPT = os.path.join(ROOT, "servers", "ts_stdio_server.mjs")
MAX_WAIT_S = 40.0
POLL_S = 0.05


def main():
    env = os.environ.copy()
    env["MIT_STDIO_MAX_BUFFER_BYTES"] = "0"  # mitigation OFF

    handle = start_stdio_server([NODE, SERVER_SCRIPT], env=env, timeout_s=10)
    if not handle.ready:
        print(json.dumps({"error": "server not ready", "lines": handle.stderr_lines}))
        return

    sampler = make_sampler(handle.pid)
    sampler_kind = type(sampler).__name__
    sampler.start()

    t0 = time.time()
    attack_result = send_unbounded_line(handle.proc, SIZE_MB)
    send_done_at = time.time()

    server_died_at = None
    deadline = t0 + MAX_WAIT_S
    while time.time() < deadline:
        if handle.proc.poll() is not None:
            server_died_at = time.time()
            break
        time.sleep(POLL_S)

    sampler.stop()
    server_exit_code = handle.proc.poll()
    time_to_oom_s = round(server_died_at - t0, 3) if server_died_at is not None else None

    result = {
        "vector": "v3_unbounded_stdio",
        "mitigation": False,
        "is_synthetic": False,
        "design": "deliberate single-shot real-OOM demonstration, NOT part of the replicated dataset",
        "sampler_kind": sampler_kind,
        "cgroup_v2_available": cgroup_v2_available(),
        "size_mb": SIZE_MB,
        "attack_result": attack_result,
        "send_elapsed_s": round(send_done_at - t0, 3),
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


if __name__ == "__main__":
    main()
