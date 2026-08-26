"""
No-attack baseline analysis (paper Sec. 3 success criterion, review defect B1).

The paper's success criterion (Sec. 3) says a vector succeeds whenever it
"measurably degrades the resource available to a concurrent, well-behaved
client -- i.e. whenever the benign-client latency or error rate moves adversely
while the attack is in progress." That is an attack-PRESENT vs attack-ABSENT
comparison. The primary Table 3 cells only vary `mitigation` (attack always
present), so on their own they measure mitigation efficacy, not the criterion.

This script closes that gap. It reads the NO-ATTACK control cells
(results/real/<vector>__control.json, produced by
`python run_replication.py --control --reps 10`) and compares, per vector, the
benign client's p95 latency and error rate with NO attack running against the
same benign client's numbers while the UNMITIGATED attack is in progress
(the OFF rows of the primary Table 3 file). It emits:

  * "Table 3b" -- the no-attack benign baseline beside the attack-present
    (unmitigated) benign numbers, with a Mann-Whitney U test of the two
    per-rep benign-p95 distributions; and
  * a per-vector verdict on whether Sec. 3's criterion is met.

Every number is transcribed by this script from committed real per-rep data.
Nothing here models or fabricates a value.
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

# a latency rise counts as "adverse" only if it is both statistically
# significant (MWU two-sided p < 0.05) and materially large; MCP round trips on
# loopback are sub-10 ms, so a >=2x median rise is the materiality bar.
ALPHA = 0.05
LATENCY_RATIO_BAR = 2.0
ERROR_RATE_BAR = 0.10  # a benign error-rate rise of >=10 points is adverse


def _kept(rows, aidx):
    return [r for r in rows if not r.get("is_synthetic")
            and (r.get("rep_index") is None or r["rep_index"] >= 0)
            and r["load_level"] == aidx]


def _paired_exists(vector):
    return (os.path.exists(os.path.join(REAL, f"{vector}__paired.json"))
            and os.path.exists(os.path.join(REAL, f"{vector}__paired_control.json")))


def load_control(vector):
    # prefer the within-session paired control (task #2), else the original
    # (cross-session) control set.
    for cand in (f"{vector}__paired_control.json", f"{vector}__control.json"):
        path = os.path.join(REAL, cand)
        if os.path.exists(path):
            return _kept(json.load(open(path, encoding="utf-8")), ANCHOR_LOAD_INDEX[vector])
    return None


def load_attack_off(vector):
    # prefer the within-session paired attack arm (task #2, measured back-to-back
    # with the paired control), else the committed anchor file.
    path = os.path.join(REAL, f"{vector}__paired.json")
    if not os.path.exists(path):
        path = os.path.join(REAL, f"{vector}.json")
    rows = _kept(json.load(open(path, encoding="utf-8")), ANCHOR_LOAD_INDEX[vector])
    return [r for r in rows if not bool(r["mitigation"])]


def session_mode():
    """'within-session' if every vector has a paired set, else 'cross-session'."""
    return "within-session" if all(_paired_exists(v) for v in ORDER) else "cross-session"


def verdict(vector, ctrl, off):
    """Return (met: bool|None, reason: str) for Sec. 3's criterion."""
    if not ctrl or not off:
        return None, "no data"
    c_p95 = [r["lat_p95_ms"] for r in ctrl]
    o_p95 = [r["lat_p95_ms"] for r in off]
    c_err = stats.mean_sd_ci([r["error_rate"] for r in ctrl])["mean"]
    o_err = stats.mean_sd_ci([r["error_rate"] for r in off])["mean"]
    c_med = stats.median_iqr(c_p95)["median"]
    o_med = stats.median_iqr(o_p95)["median"]
    mwu = stats.mann_whitney_u(c_p95, o_p95)
    p = mwu["p_value"]

    lat_adverse = (p is not None and p < ALPHA and o_med is not None
                   and c_med is not None and c_med > 0
                   and o_med / c_med >= LATENCY_RATIO_BAR)
    err_adverse = (o_err - c_err) >= ERROR_RATE_BAR

    if lat_adverse and err_adverse:
        return True, (f"benign p95 {c_med:.2f}->{o_med:.2f} ms "
                      f"({o_med / c_med:.1f}x, MWU p={p:.4f}) AND error rate "
                      f"{c_err:.2f}->{o_err:.2f}")
    if lat_adverse:
        return True, (f"benign p95 {c_med:.2f}->{o_med:.2f} ms "
                      f"({o_med / c_med:.1f}x, MWU p={p:.4f})")
    if err_adverse:
        return True, (f"benign error rate {c_err:.2f}->{o_err:.2f} "
                      f"(p95 {c_med:.2f}->{o_med:.2f} ms, MWU p={p:.4f})")
    return False, (f"benign p95 {c_med:.2f}->{o_med:.2f} ms "
                   f"(MWU p={p:.4f}), error rate {c_err:.2f}->{o_err:.2f} "
                   f"-- no material adverse move")


def main():
    mode = session_mode()
    print("### Table 3b (regenerated: no-attack benign baseline vs. "
          "attack-present, unmitigated)\n")
    print(f"_Comparison basis: **{mode}** "
          + ("(attack arm and control measured back-to-back in one session; "
             "task #2)_\n" if mode == "within-session"
             else "(control measured in a later session than the committed "
                  "anchors)_\n"))
    print("Benign p95 latency (ms, median [IQR]) and error rate for the "
          "concurrent benign client with NO attack running (control, n=10) "
          "versus the same client while the UNMITIGATED attack is in progress "
          "(Table 3 OFF cell, n=10). MWU p = two-sided Mann-Whitney U of the "
          "two per-rep benign-p95 distributions. \"Criterion met?\" answers "
          "Sec. 3 per vector.\n")
    print("| Vector | No-attack p95 med[IQR] | No-attack err | "
          "Attack-OFF p95 med[IQR] | Attack-OFF err | MWU p (control vs OFF) | "
          "Sec. 3 criterion met? |")
    print("|---|---|---|---|---|---|---|")
    n_met = 0
    n_total = 0
    verdicts = {}
    for v in ORDER:
        ctrl = load_control(v)
        off = load_attack_off(v)
        if not ctrl or not off:
            print(f"| {VLABEL[v]} | (no control data) | | | | | |")
            continue
        n_total += 1
        c95 = stats.median_iqr([r["lat_p95_ms"] for r in ctrl])
        o95 = stats.median_iqr([r["lat_p95_ms"] for r in off])
        c_err = stats.mean_sd_ci([r["error_rate"] for r in ctrl])
        o_err = stats.mean_sd_ci([r["error_rate"] for r in off])
        mwu = stats.mann_whitney_u([r["lat_p95_ms"] for r in ctrl],
                                   [r["lat_p95_ms"] for r in off])
        met, reason = verdict(v, ctrl, off)
        verdicts[v] = (met, reason)
        if met:
            n_met += 1
        met_s = {True: "**yes**", False: "no", None: "n/a"}[met]
        print(f"| {VLABEL[v]} | {stats.fmt_median_iqr(c95)} | "
              f"{c_err['mean']:.2f} | {stats.fmt_median_iqr(o95)} | "
              f"{o_err['mean']:.2f} | {mwu['p_value']:.4f} | {met_s} |")

    print(f"\n**Sec. 3 criterion met for {n_met} of {n_total} vectors** "
          f"(attack-present benign degradation vs. a measured no-attack "
          f"baseline).\n")
    print("Per-vector detail:")
    for v in ORDER:
        if v in verdicts:
            met, reason = verdicts[v]
            tag = {True: "MET", False: "not met", None: "n/a"}[met]
            print(f"  - {VLABEL[v]}: {tag} -- {reason}")


if __name__ == "__main__":
    main()
