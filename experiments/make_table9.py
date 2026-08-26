"""
Emit the Markdown for Table 9 (replicated real anchors, mean +/- 95% CI +
Mann-Whitney U), the Table 7 real pre-attack RSS means, and the Table 10
recovery means, straight from the committed per-rep real data -- so the paper's
numbers are transcribed by a script, never by hand.

Reads results/real/<vector>.json (primary anchors). Prints Markdown tables.
"""
from __future__ import annotations

import glob
import json
import os
import re

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
CPU_CHANNEL = {"v4_deep_json", "v5_tool_flood", "v7_redos"}

_BASE_RE = re.compile(r"baseline_rss_mb=([0-9.]+)")


def load_primary(vector):
    path = os.path.join(REAL, f"{vector}.json")
    rows = json.load(open(path, encoding="utf-8"))
    aidx = ANCHOR_LOAD_INDEX[vector]
    kept = [r for r in rows if not r.get("is_synthetic")
            and (r.get("rep_index") is None or r["rep_index"] >= 0)
            and r["load_level"] == aidx]
    return kept


def baseline_of(row):
    m = _BASE_RE.search(row.get("notes") or "")
    return float(m.group(1)) if m else None


def by_mit(rows, mit):
    return [r for r in rows if bool(r["mitigation"]) is mit]


def growths(rows):
    out = []
    for r in rows:
        b = baseline_of(r)
        if b is not None and r.get("peak_rss_mb") is not None:
            out.append(max(0.0, r["peak_rss_mb"] - b))
    return out


def main():
    print("### Table 9 (regenerated: replicated real anchors, mean +/- 95% CI)\n")
    print("| Vector | Mit. | Peak RSS (MB) | RSS growth (MB) | Growth red. | Mean CPU % | "
          "Benign p95 (ms) median [IQR] | Error rate | Recovery (s) | MWU p (RSS / CPU) |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    residual_note = {}
    for v in ORDER:
        rows = load_primary(v)
        off, on = by_mit(rows, False), by_mit(rows, True)
        if not off or not on:
            print(f"| {VLABEL[v]} | -- | (no data) | | | | | | | |")
            continue
        # stats
        rss_off = stats.mean_sd_ci([r["peak_rss_mb"] for r in off])
        rss_on = stats.mean_sd_ci([r["peak_rss_mb"] for r in on])
        g_off = stats.mean_sd_ci(growths(off))
        g_on = stats.mean_sd_ci(growths(on))
        cpu_off = stats.mean_sd_ci([r["mean_cpu_pct"] for r in off])
        cpu_on = stats.mean_sd_ci([r["mean_cpu_pct"] for r in on])
        p95_off = stats.median_iqr([r["lat_p95_ms"] for r in off])
        p95_on = stats.median_iqr([r["lat_p95_ms"] for r in on])
        err_off = stats.mean_sd_ci([r["error_rate"] for r in off])
        err_on = stats.mean_sd_ci([r["error_rate"] for r in on])
        rec_off = stats.mean_sd_ci([r["recovery_s"] for r in off])
        rec_on = stats.mean_sd_ci([r["recovery_s"] for r in on])
        mwu_rss = stats.mann_whitney_u([r["peak_rss_mb"] for r in off],
                                       [r["peak_rss_mb"] for r in on])
        mwu_cpu = stats.mann_whitney_u([r["mean_cpu_pct"] for r in off],
                                       [r["mean_cpu_pct"] for r in on])
        is_cpu = v in CPU_CHANNEL
        # growth reduction (mem) or CPU reduction (cpu-channel)
        if is_cpu:
            red = None
            if cpu_off["mean"] and cpu_off["mean"] > 0:
                red = 100.0 * (cpu_off["mean"] - cpu_on["mean"]) / cpu_off["mean"]
            growth_off_s = "(CPU channel)"
            growth_on_s = "(CPU channel)"
        else:
            red = None
            if g_off["mean"] and g_off["mean"] > 0:
                red = 100.0 * (g_off["mean"] - g_on["mean"]) / g_off["mean"]
            growth_off_s = stats.fmt_ci(g_off)
            growth_on_s = stats.fmt_ci(g_on)

        mwu_str = f"RSS {mwu_rss['p_value']:.4f} / CPU {mwu_cpu['p_value']:.4f}"

        def prow(mit, rss, g_s, cpu, p95, err, rec, red_s):
            last = "—" if mit else mwu_str
            print(f"| {VLABEL[v]} | {'ON' if mit else 'OFF'} | {stats.fmt_ci(rss)} | "
                  f"{g_s} | {red_s} | {stats.fmt_ci(cpu)} | {stats.fmt_median_iqr(p95)} | "
                  f"{stats.fmt_ci(err, nd=2)} | {stats.fmt_ci(rec)} | {last} |")

        prow(False, rss_off, growth_off_s, cpu_off, p95_off, err_off, rec_off, "—")
        if red is None:
            red_s = "n/a"
        else:
            sign = "-" if red >= 0 else "+"
            red_s = f"**{sign}{abs(red):.1f}%{' CPU' if is_cpu else ''}**"
        prow(True, rss_on, growth_on_s, cpu_on, p95_on, err_on, rec_on, red_s)

    print("\n(n reps per cell:", ", ".join(
        f"{v}={len(by_mit(load_primary(v), False))}" for v in ORDER), ")")

    # Table 3b -- the no-attack benign baseline (paper Sec. 3 criterion, B1).
    # Emitted here too so the single `python make_table9.py` command that
    # reproduces Table 3 also reproduces its attack-absent companion. Skipped
    # cleanly if the control sweep has not been run yet.
    import glob
    if glob.glob(os.path.join(REAL, "*__control.json")):
        print()
        try:
            import analyze_control
            analyze_control.main()
        except Exception as exc:  # never let the companion table break Table 3
            print(f"(Table 3b skipped: {exc})")
    else:
        print("\n(Table 3b: no results/real/*__control.json yet -- run "
              "`python run_replication.py --control --reps 10`)")


if __name__ == "__main__":
    main()
