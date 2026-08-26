"""
P1.1 / P1.2 batch replication runner.

Runs each vector's run_smoke.py as an isolated subprocess, SEQUENTIALLY (never
in parallel -- parallel servers would contend for CPU and corrupt the
resource measurements, and would raise host load), at:

  * the existing anchor cell            (P1.1, default)
  * a second real load point            (P1.2, --anchor2)

Usage:
  python run_replication.py --reps 10                 # P1.1 all vectors, anchor cell
  python run_replication.py --reps 8 --anchor2        # P1.2 all vectors, load+1 cell
  python run_replication.py --reps 10 --only v7_redos

Every run is a real measurement (is_synthetic=False). Nothing here models a
number. The wall-clock timeout + RSS kill-switch inside each driver stay on.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.dirname(__file__))
PY = sys.executable

VECTORS = [
    "v1_oversized_body", "v2_init_flood", "v3_unbounded_stdio", "v4_deep_json",
    "v5_tool_flood", "v6_slow_sse", "v7_redos",
]

# anchor load indices (mirror common/grid.ANCHOR_LOAD_INDEX); second point = +1
ANCHOR_LOAD_INDEX = {
    "v1_oversized_body": 3, "v2_init_flood": 3, "v3_unbounded_stdio": 3,
    "v4_deep_json": 3, "v5_tool_flood": 3, "v6_slow_sse": 3, "v7_redos": 4,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--cooldown", type=float, default=2.0)
    ap.add_argument("--anchor2", action="store_true",
                    help="run the SECOND real load point (anchor load index + 1)")
    ap.add_argument("--control", action="store_true",
                    help="run the NO-ATTACK baseline arm at each vector's anchor "
                         "cell (server up, benign probe, attack not invoked); "
                         "writes results/real/<vector>__control.json")
    ap.add_argument("--only", type=str, default=None, help="single vector name")
    args = ap.parse_args()

    vectors = [args.only] if args.only else VECTORS
    t0 = time.time()
    for v in vectors:
        env = os.environ.copy()
        cmd = [PY, os.path.join(ROOT, "vectors", v, "run_smoke.py"),
               "--reps", str(args.reps), "--cooldown", str(args.cooldown)]
        if args.anchor2:
            second = ANCHOR_LOAD_INDEX[v] + 1
            env["SMOKE_LOAD_INDEX"] = str(second)
            env["SMOKE_TAG"] = "anchor2"
            cmd += ["--tag", "anchor2"]
            print(f"\n===== {v}: SECOND anchor (load_index={second}) =====", flush=True)
        elif args.control:
            cmd += ["--control"]
            print(f"\n===== {v}: NO-ATTACK control (anchor cell) =====", flush=True)
        else:
            print(f"\n===== {v}: PRIMARY anchor =====", flush=True)
        vt0 = time.time()
        rc = subprocess.run(cmd, cwd=ROOT, env=env).returncode
        print(f"----- {v} done in {time.time()-vt0:.1f}s (rc={rc}) -----", flush=True)
        if rc != 0:
            print(f"!!!! {v} FAILED (rc={rc}); continuing to next vector", flush=True)
    print(f"\nALL DONE in {time.time()-t0:.1f}s", flush=True)


if __name__ == "__main__":
    main()
