"""
P2.1 -- Linux cgroup-v2 anchor re-run analysis.

Compares the new, real, replicated Linux/cgroup-v2 dataset
(results/real/<vector>__cgroup.json, kernel-accounted memory.peak/cpu.stat,
via common/sampler_cgroup.CgroupSampler inside the mcpdos-combined container)
against the paper's original Windows/psutil dataset
(results/real/<vector>.json, process-level psutil sampling) at each vector's
anchor cell. Both are real (is_synthetic:false); this script never touches or
overwrites the Windows dataset, only reads it for comparison.

Prints Markdown for a new paper table plus the OOM-demo summary.
"""
from __future__ import annotations

import json
import os

from common import stats
from common.grid import ANCHOR_LOAD_INDEX

ROOT = os.path.abspath(os.path.dirname(__file__))
REAL = os.path.join(ROOT, "results", "real")

VLABEL = {
    "v1_oversized_body": "v1 oversized body", "v2_init_flood": "v2 init/session flood",
    "v3_unbounded_stdio": "v3 unbounded stdio", "v4_deep_json": "v4 deep nested JSON",
    "v5_tool_flood": "v5 tool-invocation flood", "v6_slow_sse": "v6 slow-SSE",
    "v7_redos": "v7 ReDoS",
}
ORDER = ["v1_oversized_body", "v2_init_flood", "v3_unbounded_stdio", "v4_deep_json",
         "v5_tool_flood", "v6_slow_sse", "v7_redos"]


def load(path, vector):
    rows = json.load(open(path, encoding="utf-8"))
    aidx = ANCHOR_LOAD_INDEX[vector]
    return [r for r in rows if not r.get("is_synthetic")
            and (r.get("rep_index") is None or r["rep_index"] >= 0)
            and r["load_level"] == aidx]


def by_mit(rows, mit):
    return [r for r in rows if bool(r["mitigation"]) is mit]


def fmt_nonneg(values, nd=2):
    """Format a non-negative quantity, applying Table 3's note-(double-dagger) rule.

    Peak RSS and mean CPU% cannot be negative. When a cell's per-rep spread is
    wider than its mean, the symmetric t-interval's lower bound falls below
    zero and the interval is not interpretable; in that case Table 3 reports
    median [IQR] instead, and Table 4 must do the same rather than reprint an
    interval the same paper has declared uninterpretable. The switch is made
    here automatically from the data, and the cell is marked with a
    double dagger so the reader can see which convention was used.
    """
    xs = [float(v) for v in values]
    ci = stats.mean_sd_ci(xs)
    if ci["mean"] is None:
        return "n/a"
    if ci["ci_lo"] is not None and ci["ci_lo"] < 0:
        return stats.fmt_median_iqr(stats.median_iqr(xs), nd=nd) + " \u2021"
    return stats.fmt_ci(ci, nd=nd)


def main():
    print("### Table -- Linux/cgroup-v2 vs. Windows/psutil at each vector's real anchor "
          "(both REAL, n=10 reps per mitigation state)\n")
    print("| Vector | Mit. | psutil peak RSS (MB) | cgroup peak RSS (MB) | psutil CPU % | cgroup CPU % |")
    print("|---|---|---|---|---|---|")
    for v in ORDER:
        win_rows = load(os.path.join(REAL, f"{v}.json"), v)
        cg_rows = load(os.path.join(REAL, f"{v}__cgroup.json"), v)
        if not win_rows or not cg_rows:
            print(f"| {VLABEL[v]} | -- | (missing) | | | |")
            continue
        for mit in (False, True):
            w = by_mit(win_rows, mit)
            c = by_mit(cg_rows, mit)
            w_rss = fmt_nonneg([r["peak_rss_mb"] for r in w])
            c_rss = fmt_nonneg([r["peak_rss_mb"] for r in c])
            w_cpu = fmt_nonneg([r["mean_cpu_pct"] for r in w])
            c_cpu = fmt_nonneg([r["mean_cpu_pct"] for r in c])
            print(f"| {VLABEL[v]} | {'ON' if mit else 'OFF'} | {w_rss} | "
                  f"{c_rss} | {w_cpu} | {c_cpu} |")

    print("\n\u2021 Note (same rule as Table 3's note \u2021): peak RSS and mean CPU% are "
          "non-negative, so where a cell's per-rep spread is wide enough that the symmetric "
          "95% t-interval would extend below zero, the interval is not interpretable and we "
          "report median [IQR] over the 10 reps instead. Applied automatically by this script.")
    print("\n(cgroup n reps per cell:", ", ".join(
        f"{v}={len(by_mit(load(os.path.join(REAL, f'{v}__cgroup.json'), v), False))}"
        for v in ORDER), ")")

    oom_path = os.path.join(ROOT, "results", "cgroup_oom_demo.json")
    if os.path.exists(oom_path):
        oom = json.load(open(oom_path, encoding="utf-8"))
        print("\n### Real time_to_oom demonstrations (deliberate, single-shot, not part of the replicated dataset)\n")
        for vec, d in oom.items():
            if vec == "design":
                continue
            print(f"- **{vec}**: {d['note']}")
            for a in d["attempts"]:
                print(f"  - {a}")


if __name__ == "__main__":
    main()
