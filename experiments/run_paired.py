"""
Within-session paired baseline (final-corrections task #2).

Table 3b's original comparison put the no-attack control (measured in one
session) against the unmitigated-attack anchors from an EARLIER committed
session, so sub-10 ms differences for six of seven vectors were confounded by
cross-session drift. This orchestrator removes that confound: for each vector,
at the anchor cell, it runs the **unmitigated attack arm** and the **no-attack
control arm back-to-back in the same session** (same machine state, minutes
apart), so the two are directly comparable.

It writes to NEW tagged files and never overwrites the committed anchors:
  * results/real/<vector>__paired.json          (attack arm, OFF/ON, is_synthetic=False)
  * results/real/<vector>__paired_control.json  (no-attack control, is_synthetic=False)

`analyze_control.py` prefers this within-session pair when present. Every row is
a real measurement; nothing here models a number. Targets are this project's own
loopback-bound (127.0.0.1) reference servers.
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--cooldown", type=float, default=2.0)
    ap.add_argument("--only", type=str, default=None, help="single vector name")
    args = ap.parse_args()

    vectors = [args.only] if args.only else VECTORS
    t0 = time.time()
    for v in vectors:
        smoke = os.path.join(ROOT, "vectors", v, "run_smoke.py")
        # 1) attack arm (OFF/ON) -> <v>__paired.json
        print(f"\n===== {v}: PAIRED attack arm (within-session) =====", flush=True)
        rc1 = subprocess.run([PY, smoke, "--tag", "paired", "--reps", str(args.reps),
                              "--cooldown", str(args.cooldown)], cwd=ROOT).returncode
        # 2) no-attack control arm -> <v>__paired_control.json (immediately after)
        print(f"\n===== {v}: PAIRED no-attack control (within-session) =====", flush=True)
        rc2 = subprocess.run([PY, smoke, "--control", "--tag", "paired_control",
                              "--reps", str(args.reps), "--cooldown", str(args.cooldown)],
                             cwd=ROOT).returncode
        print(f"----- {v} paired done (attack rc={rc1}, control rc={rc2}) -----", flush=True)
        if rc1 != 0 or rc2 != 0:
            print(f"!!!! {v} PAIRED had a nonzero rc; continuing", flush=True)
    print(f"\nALL PAIRED DONE in {time.time()-t0:.1f}s", flush=True)


if __name__ == "__main__":
    main()
