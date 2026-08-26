"""
Surgically splice the n=10 second-load-point (anchor2) rows into
results/all_results.json (final-corrections task #3).

The synthetic sweep in all_results.json is NOT byte-reproducible on
regeneration (a single shared RNG whose draw sequence depends on the runtime),
so we must NOT rebuild the whole file just to enlarge the second load point from
n=5 to n=10. Instead we replace ONLY the real second-load-point rows in place:

  * KEEP every synthetic row and every primary-anchor real row byte-for-byte;
  * DROP the existing real rows at each vector's second load level
    (load_level = anchor+1) — these are the old n=5 anchor2 reps;
  * ADD every row from the freshly re-measured results/real/<vector>__anchor2.json
    (now n=10 per state, warm-ups included, is_synthetic=False).

This keeps Table 3, the dose-response/amplification synthetic curves, and the
94.3%->92.7% synthetic accounting change confined to exactly the intended rows.
Idempotent given the current __anchor2.json files. Verifies invariants and
refuses to write if the synthetic set would change.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from common.grid import ANCHOR_LOAD_INDEX  # noqa: E402

ROOT = os.path.abspath(os.path.dirname(__file__))
ALL = os.path.join(ROOT, "results", "all_results.json")
REAL = os.path.join(ROOT, "results", "real")


def key(r):
    return r.get("run_id")


def main():
    rows = json.load(open(ALL, encoding="utf-8"))
    second = {v: ANCHOR_LOAD_INDEX[v] + 1 for v in ANCHOR_LOAD_INDEX}

    def is_old_anchor2(r):
        return (not r["is_synthetic"]) and r["load_level"] == second.get(r["vector"])

    synth_before = sorted((key(r) for r in rows if r["is_synthetic"]))
    primary_before = sorted(key(r) for r in rows
                            if not r["is_synthetic"] and not is_old_anchor2(r))

    kept = [r for r in rows if not is_old_anchor2(r)]
    dropped = len(rows) - len(kept)

    new = []
    for v in ANCHOR_LOAD_INDEX:
        p = os.path.join(REAL, f"{v}__anchor2.json")
        vr = json.load(open(p, encoding="utf-8"))
        for r in vr:
            assert not r["is_synthetic"], (v, "synthetic row in anchor2 file?!")
            assert r["load_level"] == second[v], (v, r["load_level"], second[v])
        new += vr

    merged = kept + new

    # invariants: synthetic + primary-anchor real rows must be byte-identical sets
    synth_after = sorted(key(r) for r in merged if r["is_synthetic"])
    primary_after = sorted(key(r) for r in merged
                           if not r["is_synthetic"] and not is_old_anchor2(r))
    assert synth_after == synth_before, "synthetic set changed -- refusing to write"
    assert primary_after == primary_before, "primary-anchor set changed -- refusing to write"

    real_new = sum(1 for r in merged if not r["is_synthetic"])
    syn_new = sum(1 for r in merged if r["is_synthetic"])
    json.dump(merged, open(ALL, "w", encoding="utf-8"), indent=2)
    print(f"dropped {dropped} old anchor2 real rows; added {len(new)} new (n=10) rows")
    print(f"all_results.json now: {len(merged)} rows "
          f"({real_new} real, {syn_new} synthetic, "
          f"{100.0*syn_new/len(merged):.2f}% synthetic)")


if __name__ == "__main__":
    main()
