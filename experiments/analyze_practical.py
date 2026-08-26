"""Analyze the practical high-concurrency flood (Table 3c).

Reads results/real/<v2|v5>__practical.json and __practical_control.json.
Applies the same pre-declared Sec. 3 criterion as Table 3b (2x median p95
at MWU p<0.05, or error-rate rise >= 0.10) on the concurrent established-
session echo channel. Warm-up rows (rep_index < 0) are dropped.
"""
from __future__ import annotations

import json
import os
import re

from common import stats

ROOT = os.path.abspath(os.path.dirname(__file__))
REAL = os.path.join(ROOT, "results", "real")
ALPHA = 0.05
LATENCY_RATIO_BAR = 2.0
ERROR_RATE_BAR = 0.10
ORDER = ["v2_init_flood", "v5_tool_flood"]
VLABEL = {
    "v2_init_flood": "v2 init/session flood",
    "v5_tool_flood": "v5 tool-invocation flood",
}


def _kept(path):
    if not os.path.exists(path):
        return []
    rows = json.load(open(path, encoding="utf-8"))
    return [r for r in rows if not r.get("is_synthetic")
            and (r.get("rep_index") is None or r["rep_index"] >= 0)]


def _note_field(notes, key, default=None, cast=float):
    m = re.search(rf"{re.escape(key)}=([0-9.]+)", notes or "")
    if not m:
        return default
    try:
        return cast(m.group(1))
    except ValueError:
        return default


def verdict(ctrl, off):
    c_p95 = [r["lat_p95_ms"] for r in ctrl]
    o_p95 = [r["lat_p95_ms"] for r in off]
    c_err = stats.mean_sd_ci([r["error_rate"] for r in ctrl])["mean"]
    o_err = stats.mean_sd_ci([r["error_rate"] for r in off])["mean"]
    c_med = stats.median_iqr(c_p95)["median"]
    o_med = stats.median_iqr(o_p95)["median"]
    mwu = stats.mann_whitney_u(c_p95, o_p95)
    p = mwu["p_value"]
    lat_adverse = (p is not None and p < ALPHA and c_med and o_med
                   and c_med > 0 and o_med / c_med >= LATENCY_RATIO_BAR)
    err_adverse = (o_err - c_err) >= ERROR_RATE_BAR
    met = bool(lat_adverse or err_adverse)
    ratio = (o_med / c_med) if (c_med and o_med and c_med > 0) else None
    reason = (f"benign p95 {c_med:.2f}->{o_med:.2f} ms "
              f"({ratio:.2f}x, MWU p={p:.4f}), error rate {c_err:.3f}->{o_err:.3f}")
    return met, reason, p, c_med, o_med, c_err, o_err, mwu


def main():
    print("### Table 3c — practical sustained flood (REAL, concurrent benign probe)\n")
    print("C=32 workers/sessions, 10 s wall-clock flood, established-session "
          "echo measured *during* the attack (not after). n = kept reps; "
          "warmup discarded. Criterion identical to Table 3b.\n")
    print("| Vector | n | No-attack p95 med[IQR] | No-attack err | "
          "Attack p95 med[IQR] | Attack err | RSS ctrl->atk (MB) | "
          "MWU p (r) | Sec. 3 met? |")
    print("|---|---|---|---|---|---|---|---|---|")
    summary = {}
    for v in ORDER:
        ctrl = _kept(os.path.join(REAL, f"{v}__practical_control.json"))
        off = _kept(os.path.join(REAL, f"{v}__practical.json"))
        if not ctrl or not off:
            print(f"| {VLABEL[v]} | (missing) | | | | | | | |")
            continue
        n = min(len(ctrl), len(off))
        c95 = stats.median_iqr([r["lat_p95_ms"] for r in ctrl])
        o95 = stats.median_iqr([r["lat_p95_ms"] for r in off])
        c_err = stats.mean_sd_ci([r["error_rate"] for r in ctrl])
        o_err = stats.mean_sd_ci([r["error_rate"] for r in off])
        c_rss = stats.mean_sd_ci([r["peak_rss_mb"] for r in ctrl])
        o_rss = stats.mean_sd_ci([r["peak_rss_mb"] for r in off])
        c_cpu = stats.mean_sd_ci([r["mean_cpu_pct"] for r in ctrl])
        o_cpu = stats.mean_sd_ci([r["mean_cpu_pct"] for r in off])
        met, reason, p, c_med, o_med, ce, oe, mwu = verdict(ctrl, off)
        init_c = [_note_field(r.get("notes"), "init_err", 0.0) for r in ctrl]
        init_o = [_note_field(r.get("notes"), "init_err", 0.0) for r in off]
        print(
            f"| {VLABEL[v]} | {n} | {stats.fmt_median_iqr(c95)} | {c_err['mean']:.3f} | "
            f"{stats.fmt_median_iqr(o95)} | {o_err['mean']:.3f} | "
            f"{c_rss['mean']:.1f}->{o_rss['mean']:.1f} | "
            f"{p:.4f} (r {mwu['rank_biserial']:+.2f}) | "
            f"{'**yes**' if met else 'no'} |"
        )
        summary[v] = {
            "n": n, "met": met, "reason": reason,
            "ctrl_p95": c95, "atk_p95": o95,
            "ctrl_err": c_err["mean"], "atk_err": o_err["mean"],
            "ctrl_rss": c_rss, "atk_rss": o_rss,
            "ctrl_cpu": c_cpu, "atk_cpu": o_cpu,
            "ctrl_init_err": stats.mean_sd_ci(init_c)["mean"],
            "atk_init_err": stats.mean_sd_ci(init_o)["mean"],
            "mwu": mwu,
        }
        print(f"  detail: {reason}; init_err {summary[v]['ctrl_init_err']:.3f}->"
              f"{summary[v]['atk_init_err']:.3f}; "
              f"CPU {c_cpu['mean']:.1f}->{o_cpu['mean']:.1f}%")
    out = os.path.join(ROOT, "results", "practical_summary.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
