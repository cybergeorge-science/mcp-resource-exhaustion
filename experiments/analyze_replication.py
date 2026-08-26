"""
Aggregate the replicated real runs (P1.1/P1.2) into per-cell statistics and
mitigation OFF-vs-ON significance tests.

Reads every results/real/*.json file, groups rows by `cell_id` *and measurement
instrument*, and for each cell reports mean +/- 95% CI
(RSS/CPU/error/recovery/amplification) and median+IQR (latency percentiles) via
common/stats.py. For each (vector, transport, sdk, load_level, concurrency,
instrument) it pairs the mitigation OFF and ON cells and runs a two-sided
Mann-Whitney U on the per-rep benign p95 latency and on the per-rep peak RSS
distributions (paper Sec. 4.4's promised test), reporting p-value +
rank-biserial effect size.

IMPORTANT (instrument separation). Two independent real datasets exist for the
same anchor cells: the primary Windows/psutil dataset (results/real/<v>.json)
and the Linux/cgroup-v2 re-run (results/real/<v>__cgroup.json). They carry
identical `cell_id`s but measure different things (per-process psutil RSS/CPU
vs. per-container kernel memory.peak/cpu.stat), and the paper itself states
they are not comparable in magnitude (Sec. 5.4). They must therefore never be
pooled into one Mann-Whitney cell; `instrument_of()` below keeps them apart.

MULTIPLE-COMPARISONS FAMILY. The paper's Sec. 4 states the family as exactly
one primary-channel OFF-vs-ON test per vector (m = 7) at the Windows/psutil
ANCHOR cell. Only those seven tests enter the Holm-Bonferroni family. The
second-load-point cells and the Linux/cgroup-v2 cells are still computed and
emitted, but flagged `in_holm_family: false` and reported UNADJUSTED as
secondary results.

Writes results/stats_summary.json (consumed when regenerating Table 9) and
prints a compact human-readable summary.
"""
from __future__ import annotations

import glob
import json
import os
from collections import defaultdict

from common import stats
from common.grid import ANCHOR_LOAD_INDEX

ROOT = os.path.abspath(os.path.dirname(__file__))
REAL_DIR = os.path.join(ROOT, "results", "real")


def instrument_of(path: str) -> str:
    """Measurement instrument for a results/real/*.json file.

    Rows themselves carry no instrument field and the psutil and cgroup files
    share identical `cell_id`s, so the instrument is derived from the source
    filename: `<vector>__cgroup.json` is the Linux cgroup-v2 re-run (kernel
    memory.peak / cpu.stat, per container), everything else is the primary
    Windows/psutil per-process sampling.
    """
    return "cgroup" if os.path.basename(path).endswith("__cgroup.json") else "psutil"


def load_real_rows() -> list[dict]:
    """Load every real row, tagging each with the instrument it came from.

    The no-attack control set (`*__control.json`, marked `attack_present=no`)
    is a different experimental condition -- attack absent -- and MUST NOT be
    pooled into the attack OFF-vs-ON mitigation-efficacy family this script
    computes. Its OFF rows share a `base_key()` with the attack OFF cells (same
    vector/transport/sdk/load/concurrency/instrument), so left in they would
    silently double the OFF group. We skip the control files here by name, and
    also drop any stray `attack_present=no` row as a second guard. The control
    condition is analyzed by `analyze_control.py` (Table 3b) instead.
    """
    rows = []
    for path in sorted(glob.glob(os.path.join(REAL_DIR, "*.json"))):
        base = os.path.basename(path)
        # The no-attack / within-session baseline sets share a base_key() with
        # the primary anchors (same vector/transport/sdk/load/concurrency/
        # instrument) and would silently double a cell if pooled into the
        # OFF-vs-ON family, so they are excluded here and analyzed by
        # analyze_control.py instead: `__control` / `__paired_control` (no-attack,
        # also marked attack_present=no) and `__paired` (a within-session attack
        # arm). The `__anchor2` second-load-point set is a DIFFERENT load_level,
        # so it forms its own cells (kept, reported unadjusted, out of the Holm
        # family) and is not excluded here.
        if "__control" in base or "__paired" in base:
            continue
        inst = instrument_of(path)
        with open(path, encoding="utf-8") as fh:
            for r in json.load(fh):
                if "attack_present=no" in (r.get("notes") or ""):
                    continue
                r = dict(r)
                r["instrument"] = inst
                rows.append(r)
    return rows


def kept(rows: list[dict]) -> list[dict]:
    return [r for r in rows if not r.get("is_synthetic")
            and (r.get("rep_index") is None or r["rep_index"] >= 0)]


def base_key(r: dict) -> tuple:
    # The instrument is part of the key: Windows/psutil and Linux/cgroup reps
    # measure different quantities and must never be pooled into one test.
    return (r["vector"], r.get("transport"), r.get("sdk"),
            r["load_level"], r["concurrency"], r["instrument"])


# CPU is the primary channel for v4 and v7 (pre-specified: these vectors are
# CPU-bound and the paper headlines their CPU reduction).
#
# v5 is a POST-HOC REASSIGNMENT. Its pre-specified primary channel was CPU,
# on which the OFF-vs-ON test FAILS (v5's CPU *rises* under mitigation).
# Table 3's note * argues that rise is a sampling artifact -- rejected requests
# return almost instantly, so the sampling window fills with cheap rejections --
# and the unambiguous signal is peak RSS (96.48 -> 78.13 MB). We follow note *
# and score v5 on peak_rss_mb, but we record here, and in the paper, that this
# is a post-hoc channel change justified by note *, NOT the original
# pre-specification. v5's CPU-channel result is still emitted below as
# `mwu_mean_cpu_pct` so the failed pre-specified endpoint stays visible.
CPU_CHANNEL_VECTORS = ("v4", "v7")
POST_HOC_CHANNEL = {"v5": "peak_rss_mb"}  # see note * (post-hoc, declared)


def anchor_instrument_cell(entry: dict) -> bool:
    """True iff this comparison is the paper's Sec. 4 family member for its
    vector: the Windows/psutil PRIMARY anchor load point. Second-load-point
    cells and Linux/cgroup cells are secondary and stay out of the Holm
    family."""
    return (entry["instrument"] == "psutil"
            and entry["load_level"] == ANCHOR_LOAD_INDEX.get(entry["vector"]))


def main():
    rows = load_real_rows()
    by_cell: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        cid = r.get("cell_id") or (
            f"{r['vector']}|{r.get('transport')}|{r.get('sdk')}"
            f"|L{r['load_level']}|C{r['concurrency']}"
            f"|{'on' if r['mitigation'] else 'off'}")
        # psutil and cgroup rows share a cell_id but are different instruments;
        # suffix the cgroup ones so the two never merge into one summary cell.
        if r["instrument"] != "psutil":
            cid = f"{cid}|{r['instrument']}"
        by_cell[cid].append(r)

    cells = {cid: stats.summarize_cell(rws) for cid, rws in by_cell.items()}

    # pair OFF/ON per base cell for Mann-Whitney
    off_on: dict[tuple, dict] = defaultdict(dict)
    for r in kept(rows):
        off_on[base_key(r)]["on" if r["mitigation"] else "off"] = None
    grouped: dict[tuple, dict[str, list[dict]]] = defaultdict(lambda: {"off": [], "on": []})
    for r in kept(rows):
        grouped[base_key(r)]["on" if r["mitigation"] else "off"].append(r)

    comparisons = []
    for bkey, states in sorted(grouped.items(), key=lambda kv: str(kv[0])):
        off, on = states["off"], states["on"]
        if not off or not on:
            continue
        entry = {"vector": bkey[0], "transport": bkey[1], "sdk": bkey[2],
                 "load_level": bkey[3], "concurrency": bkey[4],
                 "instrument": bkey[5],
                 "n_off": len(off), "n_on": len(on)}
        for dv in ("lat_p95_ms", "peak_rss_mb", "mean_cpu_pct"):
            a = [r[dv] for r in off if r.get(dv) is not None]
            b = [r[dv] for r in on if r.get(dv) is not None]
            entry[f"mwu_{dv}"] = stats.mann_whitney_u(a, b)
        vtag = entry["vector"].split("_")[0]
        if vtag in POST_HOC_CHANNEL:
            entry["primary_channel"] = POST_HOC_CHANNEL[vtag]
            entry["primary_channel_post_hoc"] = True
            entry["primary_channel_note"] = (
                "post-hoc reassignment from the pre-specified CPU channel to "
                "peak RSS, justified by Table 3 note * (v5's CPU rise is a "
                "sampling artifact); not the original pre-specification")
        else:
            entry["primary_channel"] = (
                "mean_cpu_pct" if vtag in CPU_CHANNEL_VECTORS else "peak_rss_mb")
            entry["primary_channel_post_hoc"] = False
        entry["mwu_primary"] = entry[f"mwu_{entry['primary_channel']}"]
        entry["in_holm_family"] = anchor_instrument_cell(entry)
        comparisons.append(entry)

    # Holm-Bonferroni across EXACTLY the family the paper's Sec. 4 declares:
    # one primary-channel OFF-vs-ON test per vector at the Windows/psutil
    # anchor cell (m = 7). Everything else (second load point, cgroup
    # instrument) is emitted unadjusted as a secondary result.
    family = [c for c in comparisons if c["in_holm_family"]]
    holm = stats.holm_bonferroni([c["mwu_primary"]["p_value"] for c in family])
    for c, h in zip(family, holm):
        c["mwu_primary_p_holm"] = h["p_holm"]
        c["mwu_primary_reject_holm"] = h["reject"]
    for c in comparisons:
        if not c["in_holm_family"]:
            c["mwu_primary_p_holm"] = None
            c["mwu_primary_reject_holm"] = None
            c["holm_exclusion_reason"] = (
                "secondary: Linux/cgroup-v2 instrument, reported unadjusted"
                if c["instrument"] != "psutil"
                else "secondary: second real load point, reported unadjusted")

    out = {"cells": cells, "comparisons": comparisons,
           "n_real_rows": len(kept(rows)),
           "multiple_comparisons": {
               "method": "holm-bonferroni",
               "family": ("one primary-channel OFF-vs-ON test per vector at the "
                          "Windows/psutil anchor cell"),
               "family_members": [f"{c['vector']}|L{c['load_level']}"
                                  f"|{c['primary_channel']}" for c in family],
               "excluded_from_family": (
                   "second-real-load-point cells and Linux/cgroup-v2 cells; these "
                   "are computed and emitted but reported unadjusted"),
               "n_tests": sum(1 for c in family
                              if c["mwu_primary"]["p_value"] is not None),
               "alpha": 0.05}}
    out_path = os.path.join(ROOT, "results", "stats_summary.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"wrote {out_path}")

    # human-readable
    print(f"\n{len(kept(rows))} kept real rows across {len(cells)} cells\n")
    for cid in sorted(cells):
        c = cells[cid]
        if c["n_reps"] == 0:
            continue
        print(f"{cid}  (n={c['n_reps']})")
        print(f"    peak_rss_mb : {stats.fmt_ci(c['peak_rss_mb'])}")
        print(f"    mean_cpu_pct: {stats.fmt_ci(c['mean_cpu_pct'])}")
        print(f"    lat_p95_ms  : {stats.fmt_median_iqr(c['lat_p95_ms'])}")
        print(f"    error_rate  : {stats.fmt_ci(c['error_rate'], nd=3)}")
        print(f"    recovery_s  : {stats.fmt_ci(c['recovery_s'])}")
    def _line(e, with_holm):
        prim = e["mwu_primary"]
        p = prim["p_value"]
        rrb = prim["rank_biserial"]
        pstr = f"{p:.6f}" if p is not None else "n/a"
        tail = ""
        if with_holm:
            ph = e.get("mwu_primary_p_holm")
            rej = "reject" if e.get("mwu_primary_reject_holm") else "retain"
            phstr = f"{ph:.6f}" if ph is not None else "n/a"
            tail = f" -> p_holm={phstr} ({rej})"
        flag = " [POST-HOC channel]" if e.get("primary_channel_post_hoc") else ""
        print(f"  {e['vector']} L{e['load_level']} C{e['concurrency']} "
              f"{e['instrument']} [{e['primary_channel']}]{flag} "
              f"(n_off={e['n_off']},n_on={e['n_on']}): "
              f"p={pstr} rrb={rrb:+.2f}{tail}")

    fam = [e for e in comparisons if e["in_holm_family"]]
    sec = [e for e in comparisons if not e["in_holm_family"]]
    print(f"\nPRIMARY family (m={len(fam)}): one primary-channel OFF-vs-ON test "
          "per vector at the Windows/psutil anchor cell, Holm-Bonferroni corrected:")
    for e in fam:
        _line(e, True)
    print("\nSECONDARY (NOT in the Holm family; reported UNADJUSTED): "
          "second real load point and Linux/cgroup-v2 instrument:")
    for e in sec:
        _line(e, False)


if __name__ == "__main__":
    main()
