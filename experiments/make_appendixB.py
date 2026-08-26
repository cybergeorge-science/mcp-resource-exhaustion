"""
Emit Appendix B (the SYNTHETIC full-sweep tables, P3.1) as Markdown from
results/all_results.json. One table per vector: load 1-5, mitigation OFF/ON, at
that vector's anchor transport/SDK/concurrency. The anchor-load row shows the
REPLICATED REAL mean (is_synthetic:false, mean of reps); every other row is the
modeled sweep mean (is_synthetic:true, mean of the seeded replicates). Labeled
throughout so no synthetic value is mistaken for a measurement.
"""
from __future__ import annotations

import json
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from common.grid import ANCHOR_LOAD_INDEX, REAL_ANCHOR, LOAD_LEVELS

ROOT = os.path.abspath(os.path.dirname(__file__))
VLABEL = {
    "v1_oversized_body": "v1 — oversized body", "v2_init_flood": "v2 — init/session flood",
    "v3_unbounded_stdio": "v3 — unbounded stdio", "v4_deep_json": "v4 — deep nested JSON",
    "v5_tool_flood": "v5 — tool-invocation flood", "v6_slow_sse": "v6 — slow-SSE",
    "v7_redos": "v7 — ReDoS",
}
ORDER = list(VLABEL)


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else 0.0


def main():
    rows = json.load(open(os.path.join(ROOT, "results", "all_results.json"), encoding="utf-8"))
    print("## Appendix B — Synthetic full-sweep tables (SYNTHETIC, illustrative)\n")
    print("Every row marked SYNTH is `is_synthetic:true`: a documented power-law "
          "extrapolation (Section 4.4, `common/synth_model.py`) anchored to the "
          "replicated real means of Table 9, **not a measurement**. The single REAL "
          "row per block is the replicated real anchor (mean of ≥10 reps). Figure 2 "
          "plots these curves with the real anchors overlaid.\n")
    for v in ORDER:
        aidx = ANCHOR_LOAD_INDEX[v]
        anc = REAL_ANCHOR[v]
        tr, sdk = anc["transport"], anc["sdk"]
        # anchor concurrency from a real row
        real_rows = [r for r in rows if r["vector"] == v and not r["is_synthetic"]
                     and (r.get("rep_index") is None or r["rep_index"] >= 0)
                     and r["load_level"] == aidx]
        conc = real_rows[0]["concurrency"] if real_rows else 1
        unit = LOAD_LEVELS[v]["unit"]
        print(f"\n**{VLABEL[v]} ({tr}, {sdk}, concurrency={conc}; load unit: {unit})**\n")
        print("| Load | Mit | Peak RSS (MB) | Mean CPU % | p95 lat (ms) | Error rate | Recovery (s) | Real? |")
        print("|---|---|---|---|---|---|---|---|")
        for mit in (False, True):
            for load in range(1, 6):
                if load == aidx:
                    grp = [r for r in rows if r["vector"] == v and not r["is_synthetic"]
                           and (r.get("rep_index") is None or r["rep_index"] >= 0)
                           and r["load_level"] == load and bool(r["mitigation"]) is mit]
                    tag = "**REAL**"
                else:
                    grp = [r for r in rows if r["vector"] == v and r["is_synthetic"]
                           and r.get("transport") == tr and r.get("sdk") == sdk
                           and r["load_level"] == load and r["concurrency"] == conc
                           and bool(r["mitigation"]) is mit]
                    tag = "SYNTH"
                if not grp:
                    continue
                b = "**" if tag == "**REAL**" else ""
                print(f"| {b}{load}{b} | {b}{'ON' if mit else 'OFF'}{b} | "
                      f"{b}{mean([r['peak_rss_mb'] for r in grp]):.2f}{b} | "
                      f"{b}{mean([r['mean_cpu_pct'] for r in grp]):.2f}{b} | "
                      f"{b}{mean([r['lat_p95_ms'] for r in grp]):.2f}{b} | "
                      f"{b}{mean([r['error_rate'] for r in grp]):.2f}{b} | "
                      f"{b}{mean([r['recovery_s'] for r in grp]):.2f}{b} | {tag} |")


if __name__ == "__main__":
    main()
